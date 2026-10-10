//! Table privileges derived from the declared access rules.
//!
//! Provisioning grants `SELECT ON ALL TABLES` to `anon` and full CRUD to
//! `authenticated`, with matching default privileges so every future table inherits
//! them. RLS is then the only thing standing between an unauthenticated caller and
//! every row of every table -- a single layer, where a policy that fails to apply
//! (an unmarked table, a mistaken drop, a bug in this engine) has nothing behind it.
//!
//! The access rules already say which operations are reachable, so the privileges
//! can say the same thing. A model with no `read` rule denies every select, so
//! `anon` and `authenticated` do not need `SELECT` on it at all.
//!
//! **Conservative in one direction only.** A privilege is revoked only when the
//! rules prove it can never be used. Anything this analysis cannot decide keeps its
//! grant, because a wrong revoke breaks a working application while a missed one
//! merely leaves today's behaviour in place. `service_role` is never touched: it is
//! the escape hatch that has to keep working when everything else is locked down.

use crate::parser::accessors::{column_names_for, db_table_name, platform_access};
use crate::parser::ast::{AccessRule, MembershipSource, ModelAst, Operand, SchemaAst};
use crate::sql_quote::{quote_ident, quote_literal, quote_qualified};

/// Whether an unauthenticated caller could ever satisfy a rule.
///
/// Only a proof of *unreachability* is acted on, so every uncertain case answers
/// true and the grant survives.
fn reachable_by_anon(rule: &AccessRule) -> bool {
    match rule {
        // Constraint-only. `Matches` is refused inside an `access` rule by the CLI, so this arm is
        // reached only if an AST is hand-written; treating it as caller-independent is the safe
        // reading, since the pattern says nothing about who is asking.
        AccessRule::Matches { .. } => true,
        AccessRule::Public => true,
        AccessRule::Private => false,

        // `auth.uid()` is null for an unauthenticated caller.
        AccessRule::Authenticated => false,

        // Ownership compares against `auth.uid()`, which no anonymous caller has.
        AccessRule::Owner { .. } => false,

        // App roles come from the token's claims. Without one the caller's role is
        // `anon`, so only a rule naming it is reachable.
        AccessRule::Role { roles } => roles.iter().any(|r| r == "anon"),

        AccessRule::Any { rules } => rules.iter().any(reachable_by_anon),
        AccessRule::All { rules } => rules.iter().all(reachable_by_anon),

        // Negation of an unreachable rule is reachable, but proving that needs the
        // rule to be total; not worth the risk of a wrong revoke.
        AccessRule::Not { .. } => true,

        AccessRule::Compare { left, right, .. } => {
            operand_reachable_by_anon(left) && operand_reachable_by_anon(right)
        }
        AccessRule::NullCheck { operand, .. } => operand_reachable_by_anon(operand),

        // Membership is against the caller's own rows, so an anonymous caller
        // matches nothing -- unless the source is a fixed list, which is the same
        // for everyone.
        AccessRule::In { source, .. } | AccessRule::Exists { source } => {
            matches!(source, MembershipSource::Literal { .. })
        }
    }
}

fn operand_reachable_by_anon(operand: &Operand) -> bool {
    match operand {
        // Both are absent for an anonymous caller, so any comparison against them
        // is null and therefore false.
        Operand::AuthUid | Operand::Claim { .. } => false,
        // `auth.role()` falls back to 'anon', so a comparison can still match.
        Operand::AuthRole => true,
        _ => true,
    }
}

/// The roles whose privileges on a model table the engine decides. `service_role` is never
/// touched: it is the escape hatch that has to keep working when everything else is locked down.
pub const GRANTED_ROLES: [&str; 2] = ["anon", "authenticated"];

/// The table privileges the access rules govern, in the order Postgres sorts their names, which
/// is how the catalog reports a privilege set.
const RULED: [&str; 4] = ["DELETE", "INSERT", "SELECT", "UPDATE"];

/// Everything one API role may do on one model table: the ledger object (Phase 4.7c, D7).
///
/// One object for the table's privileges and its column privileges together, because Postgres
/// does not keep them apart: revoking a table privilege revokes it on every column too, so a
/// table grant replaced on its own would silently take its column grants with it.
///
/// **The exact set.** Applied as `REVOKE ALL` and then the grants, so nothing else survives: the
/// image's default privileges had left `anon` and `authenticated` holding `TRUNCATE` (which
/// row-level security does not govern), `REFERENCES`, `TRIGGER` and `MAINTAIN` on every model
/// table. Grants to any other role are not this object's and are never touched.
///
/// **Conservative in one direction only.** A privilege is revoked only when the rules prove it can
/// never be used, as the module documentation says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableGrant {
    pub table: String,
    pub role: &'static str,
    /// Table-level privileges, sorted as the catalog sorts them.
    pub privileges: Vec<&'static str>,
    /// Write privileges narrowed to columns: the operation, and the columns it may not touch. The
    /// operation is then not in `privileges`.
    pub narrowed: Vec<(&'static str, Vec<String>)>,
    /// The columns the model declares, its options' included, in declaration order: what a
    /// narrowed privilege is granted on, less the columns it may not touch. Part of the `CREATE`,
    /// so a column added to or dropped from the schema changes what the push intends and the
    /// grant is applied again, rather than leaving a new column unwritable for the role (or a
    /// dropped one reading as privileges changed outside Supatype).
    pub columns: Vec<String>,
}

impl TableGrant {
    /// The privilege set as the catalog's fingerprint labels it.
    pub fn privilege_set(&self) -> String {
        self.privileges.join(",")
    }

    /// Revoke everything, then grant exactly this set, applied only if the role exists: a
    /// self-hosted database may not have the API roles at all, and a `GRANT` to a role that does
    /// not exist would abort the whole migration. One block per role and table, so the ledger
    /// attributes it to one object (`crate::desired::statements`).
    pub fn create_sql(&self, schema: &str) -> String {
        let target = quote_qualified(schema, &self.table);
        let role = self.role;
        let mut body = execute(&format!("REVOKE ALL PRIVILEGES ON {target} FROM {role}"));
        if !self.privileges.is_empty() {
            let grant = format!("GRANT {} ON {target} TO {role}", self.privileges.join(", "));
            body.push_str(&execute(&grant));
        }
        for (op, excluded) in &self.narrowed {
            let writable: Vec<&str> = self
                .columns
                .iter()
                .filter(|c| !excluded.contains(c))
                .map(String::as_str)
                .collect();
            body.push_str(&column_grant(schema, &self.table, op, role, &writable));
        }
        let declare = if self.narrowed.is_empty() {
            ""
        } else {
            "DECLARE\n  granted text;\n"
        };
        format!(
            "DO $grants$\n{declare}BEGIN\n  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {}) THEN\n{body}  END IF;\nEND\n$grants$;",
            quote_literal(role)
        )
    }
}

/// The statement that takes every privilege `role` holds on a table away, guarded on the role and
/// the table existing: the drop of a [`TableGrant`].
///
/// The role comes from the ledger row, so it is quoted like any other name read back.
pub fn revoke_all_sql(schema: &str, table: &str, role: &str) -> String {
    let target = quote_qualified(schema, table);
    format!(
        "DO $grants$\nBEGIN\n  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {})\n     AND to_regclass({}) IS NOT NULL THEN\n{}  END IF;\nEND\n$grants$;",
        quote_literal(role),
        quote_literal(&target),
        execute(&format!(
            "REVOKE ALL PRIVILEGES ON {target} FROM {}",
            quote_ident(role)
        ))
    )
}

/// One `EXECUTE` line of a `DO` block: `sql` as a literal.
fn execute(sql: &str) -> String {
    format!("    EXECUTE {};\n", quote_literal(sql))
}

/// Every model table's [`TableGrant`] for each API role.
///
/// `views` is tier 2 of field masking: the API reads the `api` views, so the privileges follow
/// them and the base table holds nothing for the API roles, or `Accept-Profile` walks straight
/// round the mask. Schema exposure is PostgREST configuration, not a boundary. The views' own
/// privileges are re-asserted with them ([`generate_view_grants`]).
///
/// `service_role` keeps its base-table access: tier 1 masks a `service_role` caller like any other
/// (the read predicate simply fails for it), while under tier 2 that caller reads the table
/// directly and sees everything. Deliberate, and recorded rather than quietly true.
pub fn table_grants(ast: &SchemaAst, views: bool) -> Vec<TableGrant> {
    let mut out = Vec::new();
    for model in &ast.models {
        for role in GRANTED_ROLES {
            out.push(if views {
                TableGrant {
                    table: db_table_name(model).to_string(),
                    role,
                    privileges: Vec::new(),
                    narrowed: Vec::new(),
                    columns: Vec::new(),
                }
            } else {
                model_grant(model, role)
            });
        }
    }
    out
}

/// What `role` may do on `model`'s table under its rules. `authenticated` keeps a privilege
/// whenever the operation is declared at all: which *rows* it may touch is the policy's business,
/// and revoking here would stop the policy ever being consulted. `anon` holds it only where the
/// rule can reach it.
fn model_grant(model: &ModelAst, role: &'static str) -> TableGrant {
    let access = platform_access(model);
    let rule_for = |privilege: &str| match privilege {
        "SELECT" => access.read.as_ref(),
        "INSERT" => access.create.as_ref(),
        "UPDATE" => access.update.as_ref(),
        _ => access.delete.as_ref(),
    };
    let mut privileges = Vec::new();
    let mut narrowed = Vec::new();
    for privilege in RULED {
        let allowed = match (role, rule_for(privilege)) {
            (_, None) => false,
            ("anon", Some(rule)) => reachable_by_anon(rule),
            (_, Some(_)) => true,
        };
        if !allowed {
            continue;
        }
        let mut excluded = unwritable_columns(model, privilege, role);
        if excluded.is_empty() {
            privileges.push(privilege);
        } else {
            // Narrowed to columns anyway: none on a column Postgres refuses to write (a generated
            // one, a `GENERATED ALWAYS` identity), which a table-level privilege leaves to it.
            for (name, field) in &model.fields {
                if crate::parser::accessors::never_written(field) {
                    for column in column_names_for(name, field) {
                        if !excluded.contains(&column) {
                            excluded.push(column);
                        }
                    }
                }
            }
            narrowed.push((privilege, excluded));
        }
    }
    TableGrant {
        table: db_table_name(model).to_string(),
        role,
        privileges,
        narrowed,
        columns: declared_columns(model),
    }
}

/// Every column `model` declares, by a field or an option, once each, in declaration order.
fn declared_columns(model: &ModelAst) -> Vec<String> {
    let mut columns: Vec<String> = Vec::new();
    let fields = model
        .fields
        .iter()
        .flat_map(|(name, field)| column_names_for(name, field));
    let options = crate::generator::sql::migration::option_columns(model)
        .into_iter()
        .map(|(column, _)| column.to_string());
    for column in fields.chain(options) {
        if !column.is_empty() && !columns.contains(&column) {
            columns.push(column);
        }
    }
    columns
}

// ─── Column privileges for field write rules (defence in depth) ──────────────

/// The columns `role` provably can never write on `op` (`fields.write`), which its write
/// privilege is narrowed to exclude: a second layer under the masking extension.
///
/// **Writes only.** A column `REVOKE` for reads makes `GET /table` with no `select` return
/// 403 for the whole table, which is the break the field-access design exists to avoid.
/// Writes have no such problem: `PATCH`/`POST` naming a column the role may not write is
/// *supposed* to fail.
///
/// This is a second layer, not the mechanism. Enforcement is the query rewrite, which can
/// express `Role<"admin">`; a column privilege cannot, because an application role is a JWT
/// claim and an admin still connects as `authenticated`. So only what a *database role*
/// provably can never write is excluded here.
pub fn unwritable_columns(model: &ModelAst, op: &str, role: &str) -> Vec<String> {
    if !matches!(op, "INSERT" | "UPDATE") {
        return Vec::new();
    }
    platform_access(model)
        .fields
        .iter()
        .filter(|(_, rules)| {
            rules
                .write
                .as_ref()
                .is_some_and(|write| !write_satisfiable(op, role, write))
        })
        .map(|(column, _)| column.clone())
        .collect()
}

/// Tier 2's privileges on the `api` views, for each API role: what the rules allow, re-asserted
/// with the views, which a push makes again every time. The base tables hold nothing for these
/// roles then ([`table_grants`]).
pub fn generate_view_grants(ast: &SchemaAst, view_schema: &str) -> String {
    let mut blocks = Vec::new();
    for model in &ast.models {
        for role in GRANTED_ROLES {
            let grant = model_grant(model, role);
            let target = quote_qualified(view_schema, &grant.table);
            let statements: Vec<String> = RULED
                .iter()
                .map(|privilege| {
                    let narrowed = grant.narrowed.iter().any(|(op, _)| op == privilege);
                    if grant.privileges.contains(privilege) || narrowed {
                        format!("GRANT {privilege} ON {target} TO {role}")
                    } else {
                        format!("REVOKE {privilege} ON {target} FROM {role}")
                    }
                })
                .collect();
            blocks.push(guarded_block(role, &statements));
        }
    }
    blocks.join("\n")
}

/// The privileges for one role, applied only if the role exists.
fn guarded_block(role: &str, statements: &[String]) -> String {
    let body = statements.iter().map(|s| execute(s)).collect::<String>();
    format!(
        "DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {}) THEN
{body}  END IF;
END
$grants$;
",
        quote_literal(role)
    )
}

/// Whether any caller connecting as `role` could ever satisfy this write rule for `op`.
///
/// Conservative in one direction only, like the table grants: a wrong revoke breaks a working
/// app, a missed one just leaves today's behaviour. So this answers true unless the rule
/// *proves* otherwise.
fn write_satisfiable(op: &str, role: &str, write: &AccessRule) -> bool {
    if role == "anon" {
        return reachable_by_anon(write);
    }

    // `authenticated` is every signed-in caller, so an application-role or ownership rule is
    // satisfiable by *some* of them and the column privilege must stay.
    if matches!(write, AccessRule::Private) {
        return false;
    }

    // On INSERT there is no row yet: the masking extension evaluates the write predicate
    // against `NULL::t`, so a rule that reads the row yields NULL for every caller. Nobody
    // can write the column on this path, which makes the privilege provably unusable,
    // whereas on UPDATE the same rule is satisfiable and the privilege must stay.
    if op == "INSERT" && crate::differ::field_access_diff::rule_is_row_dependent(write) {
        return false;
    }

    true
}

/// Grant `op` on `columns`, inside a block already guarded on the role: the declared columns the
/// role may write.
///
/// The list is the schema's, so it is part of what the push intends and a declared column added
/// later is granted when it is added. A column someone added outside the schema is not Supatype's
/// (D4) and gets no privilege from it. Each name is checked against `information_schema.columns`
/// at apply time, so a declared column that is not there yet never aborts the migration.
fn column_grant(schema: &str, table: &str, op: &str, role: &str, columns: &[&str]) -> String {
    if columns.is_empty() {
        return String::new();
    }
    let column_list = columns
        .iter()
        .map(|column| quote_literal(column))
        .collect::<Vec<_>>()
        .join(", ");
    // `format`'s pattern is a literal of its own, holding the target's quoted name.
    let grant = quote_literal(&format!(
        "GRANT {op} (%s) ON {} TO {role}",
        quote_qualified(schema, table)
    ));
    format!(
        "    SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position)
      INTO granted
      FROM information_schema.columns
     WHERE table_schema = {schema_literal}
       AND table_name = {table_literal}
       AND column_name IN ({column_list});
    IF granted IS NOT NULL THEN
      EXECUTE format({grant}, granted);
    END IF;
",
        schema_literal = quote_literal(schema),
        table_literal = quote_literal(table),
    )
}

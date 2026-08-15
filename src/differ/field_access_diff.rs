//! A required column nobody can write is a table nobody can insert into.
//!
//! The failure without this check is `23502 not-null violation`, which points the developer
//! at the column's NOT NULL constraint — the one thing in the picture that is not the
//! problem. The rule, the constraint and the absence of a default are all visible here, so
//! the contradiction can be named at `diff` time instead.

use crate::parser::accessors::{db_table_name, platform_access, resolve_owner_column};
use crate::parser::ast::{AccessRule, FieldAst, ModelAst, Operand, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::{bail, Result};

/// Whether a rule's outcome depends on the row it is tested against.
///
/// Not the same question as identity-dependence, which
/// `supatype-auth/internal/studiobootstrap` answers for cache safety: `Role<"admin">`
/// depends on the caller and not the row, `Lte<"published_at", Now>` on the row and not the
/// caller. Row-dependence is what matters here, because the masking extension evaluates a
/// write predicate against `NULL::t` on INSERT — there is no row yet — so a row-dependent
/// rule yields NULL, which is not `true`, for *every* caller.
pub(crate) fn rule_is_row_dependent(rule: &AccessRule) -> bool {
    match rule {
        AccessRule::Public | AccessRule::Private | AccessRule::Authenticated => false,
        AccessRule::Role { .. } => false,
        // `Owner<"author_id">` compares a column to the caller.
        AccessRule::Owner { .. } => true,
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter().any(rule_is_row_dependent)
        }
        AccessRule::Not { rule } => rule_is_row_dependent(rule),
        AccessRule::Compare { left, right, .. } => {
            operand_is_row_dependent(left) || operand_is_row_dependent(right)
        }
        // Membership and existence tests correlate a column of this row against another
        // table.
        AccessRule::In { .. } | AccessRule::Exists { .. } => true,
        // An unrecognised rule is assumed row-dependent, which only ever suppresses a
        // diagnostic — never adds a false refusal.
        _ => true,
    }
}

fn operand_is_row_dependent(operand: &Operand) -> bool {
    matches!(operand, Operand::Column { .. })
}

/// Whether a caller could ever satisfy this write rule on an INSERT.
fn writable_on_insert(rule: &AccessRule) -> bool {
    !matches!(rule, AccessRule::Private) && !rule_is_row_dependent(rule)
}

/// Whether a row can acquire a value for this column without the caller supplying one.
///
/// Three of the four sources a row can get a value from are visible in the AST: a column
/// `DEFAULT`, and the identity-like `Serial` / `BigSerial` types. (The AST has no
/// `GENERATED` concept.) The fourth — a `BEFORE INSERT` trigger — is in the database, and is
/// handled by the caller.
fn has_value_source(field: &FieldAst) -> bool {
    // `Serial` / `BigSerial` carry an implicit sequence default, and a `Slug` is populated by
    // a generated BEFORE INSERT trigger — both are value sources the caller need not supply.
    if matches!(
        field,
        FieldAst::Serial(_) | FieldAst::BigSerial(_) | FieldAst::Slug(_)
    ) {
        return true;
    }
    // An enum default is a plain variant name rather than a `DefaultValueAst`.
    if let FieldAst::Enum(f) = field {
        return f.default.is_some();
    }
    field_default(field).is_some()
}

fn field_default(field: &FieldAst) -> Option<&crate::parser::ast::DefaultValueAst> {
    match field {
        FieldAst::Text(f)
        | FieldAst::RichText(f)
        | FieldAst::Email(f)
        | FieldAst::Url(f)
        | FieldAst::Uuid(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
        | FieldAst::BigInt(f)
        | FieldAst::SmallInt(f)
        | FieldAst::Date(f)
        | FieldAst::Timestamp(f)
        | FieldAst::Serial(f)
        | FieldAst::BigSerial(f)
        | FieldAst::Money(f)
        | FieldAst::Ip(f)
        | FieldAst::Cidr(f)
        | FieldAst::Macaddr(f)
        | FieldAst::Interval(f)
        | FieldAst::TsQuery(f)
        | FieldAst::TsVector(f)
        | FieldAst::Xml(f)
        | FieldAst::Bytes(f)
        | FieldAst::Color(f) => f.default.as_ref(),
        _ => None,
    }
}

fn field_is_required(field: &FieldAst) -> bool {
    crate::differ::column_diff::field_is_required(field).unwrap_or(false)
}

/// Does the database already fill this column with a `BEFORE INSERT` row trigger?
fn before_insert_trigger(db: &DatabaseState, table: &str) -> bool {
    db.triggers.iter().any(|trigger| {
        trigger.table == table
            && trigger.timing.eq_ignore_ascii_case("BEFORE")
            && trigger.event.eq_ignore_ascii_case("INSERT")
    })
}

/// Whether the table exists in the introspected state.
///
/// When it does not — a brand new table, or a `diff` run with no connection — a
/// `BEFORE INSERT` trigger cannot be ruled out, so the contradiction is reported as a
/// warning rather than refused. Never a false refusal; the error arrives on the next push,
/// once the table is real and the absence of a trigger is a fact.
fn table_is_introspected(db: &DatabaseState, table: &str) -> bool {
    db.tables.iter().any(|t| t.name == table)
}

pub fn validate(ast: &SchemaAst, db: &DatabaseState, warnings: &mut Vec<String>) -> Result<()> {
    for model in &ast.models {
        let table = db_table_name(model);
        let access = platform_access(model);
        if access.fields.is_empty() {
            continue;
        }

        for (field_name, field) in &model.fields {
            let column = resolve_owner_column(model, field_name);
            let Some(rules) = access.fields.get(&column) else {
                continue;
            };
            let Some(write) = rules.write.as_ref() else {
                continue;
            };

            if !field_is_required(field) || has_value_source(field) {
                continue;
            }

            let problem = describe_problem(model, write, &column, table);
            let Some(problem) = problem else { continue };

            if before_insert_trigger(db, table) {
                continue;
            }

            if table_is_introspected(db, table) {
                bail!("{problem}");
            }
            warnings.push(format!("{problem} (not refused: \"{table}\" is not in the introspected state, so a BEFORE INSERT trigger cannot be ruled out)"));
        }
    }

    Ok(())
}

/// The two cases the rules *prove* are broken. Everything undecidable stays silent, for the
/// same reason the derived privileges only revoke what they can prove unusable: a wrong
/// refusal breaks a working schema, a missed one just leaves today's behaviour.
fn describe_problem(
    model: &ModelAst,
    write: &AccessRule,
    column: &str,
    table: &str,
) -> Option<String> {
    let create = platform_access(model).create.as_ref();

    // Nobody can write it, so nobody can insert a row at all.
    if !writable_on_insert(write) {
        let why = if matches!(write, AccessRule::Private) {
            "its write rule denies every caller"
        } else {
            "its write rule depends on the row, and there is no row yet when a value is \
             checked on INSERT"
        };
        return Some(format!(
            "\"{table}\".\"{column}\" is required, has no default, and {why} — so no caller \
             can ever insert a row. Give the column a default, relax the field's write rule \
             to one that does not read the row (a role or claim check), or make the column \
             optional."
        ));
    }

    // Some callers can insert but cannot write it. Only provable when `create` admits
    // everyone and the write rule does not.
    if matches!(create, Some(AccessRule::Public)) && !matches!(write, AccessRule::Public) {
        return Some(format!(
            "\"{table}\".\"{column}\" is required and has no default, but its write rule is \
             narrower than the table's create rule, which is public — so a caller who may \
             insert cannot supply it. Give the column a default, widen the field's write \
             rule, or narrow the table's create rule."
        ));
    }

    None
}

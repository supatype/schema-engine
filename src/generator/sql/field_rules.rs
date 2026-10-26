//! Field rules as tier 2 evaluates them: inline, as fast as a rule on roles, claims or the row's
//! own columns always was, with every read of another table moved into a set helper.
//!
//! A rule that reads another table (`In<col, Rows<...>>`, `Exists<Rows<...>>`, or `Owner` through a
//! relation) must be answered by the app's rules: a Studio user reads every row of every table,
//! and an inline `EXISTS` would make every team theirs. So that read runs in a helper with
//! [`IN_RULE_SETTING`] on, which the Studio policies stand aside for. The helper answers for the
//! caller, not the row: the keys of the source rows they may read, or whether there are any. The
//! view calls it as an uncorrelated subquery, which Postgres evaluates once per statement, and each
//! row is tested against the answer, so a membership costs a hash probe per row rather than a
//! function call and an index lookup.
//!
//! A helper is `SECURITY DEFINER` as the view owner, because the source table is one the API roles
//! hold nothing on under tier 2, exactly as the owner-rights view read it inline; row-level
//! security still applies to the owner and reads the caller's claims. `search_path` is pinned
//! empty, and everything a helper names is qualified. Callable by the API roles only, which call it
//! through the views, and it tells a caller nothing they could not read: the keys of rows the app's
//! rules show them.

use std::collections::BTreeMap;

use crate::generator::sql::auth_functions::API_ROLES;
use crate::generator::sql::rls::{
    access_rule_to_expr, owner_column, owner_join, rows_filter_sql, AUTH_UID, IN_RULE_SETTING,
};
use crate::parser::accessors::db_table_name;
use crate::parser::ast::{AccessRule, MembershipSource, ModelAst, SchemaAst};
use crate::sql_quote::{dollar_quote, quote_ident, quote_qualified};

/// Where the set helpers live: the helper schema, which the API never serves, so no helper is
/// ever an RPC.
pub const RULE_SCHEMA: &str = crate::generator::sql::versions::HELPER_SCHEMA;

/// One set helper: `rule_set_<hash>()`, named by what it returns and reads, so two rules asking the
/// same question share it and a changed question is a new helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    pub name: String,
    returns: String,
    body: String,
}

impl RuleSet {
    fn new(returns: String, body: String) -> Self {
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(format!("{returns}\n{body}").as_bytes()));
        RuleSet {
            name: format!("rule_set_{}", &hash[..12]),
            returns,
            body,
        }
    }

    /// The call, qualified.
    pub fn call(&self) -> String {
        format!("{}()", quote_qualified(RULE_SCHEMA, &self.name))
    }

    /// The helper, owned by `owner`, with execute for the API roles only.
    pub fn create_sql(&self, owner: &str) -> String {
        let signature = self.call();
        let body = dollar_quote(&format!("\n    {};\n  ", self.body), "rule");
        format!(
            "CREATE OR REPLACE FUNCTION {signature} RETURNS {returns}\n\
             \x20 LANGUAGE sql STABLE SECURITY DEFINER\n\
             \x20 SET search_path = '' SET {IN_RULE_SETTING} = 'on' AS {body};\n\
             ALTER FUNCTION {signature} OWNER TO {owner};\n\
             REVOKE ALL ON FUNCTION {signature} FROM PUBLIC;\n\
             GRANT EXECUTE ON FUNCTION {signature} TO {roles};\n\n",
            returns = self.returns,
            owner = quote_ident(owner),
            roles = API_ROLES.join(", "),
        )
    }
}

/// Renders one model's field rules for tier 2, collecting the set helpers they call.
pub struct FieldRules<'a> {
    ast: &'a SchemaAst,
    model: &'a ModelAst,
    schema: &'a str,
    sets: BTreeMap<String, RuleSet>,
}

impl<'a> FieldRules<'a> {
    pub fn new(ast: &'a SchemaAst, model: &'a ModelAst, schema: &'a str) -> Self {
        FieldRules {
            ast,
            model,
            schema,
            sets: BTreeMap::new(),
        }
    }

    /// The helpers the rules rendered so far call, by name.
    pub fn into_sets(self) -> BTreeMap<String, RuleSet> {
        self.sets
    }

    /// `rule` as SQL over the model's row, every read of another table a set helper's.
    pub fn expr(&mut self, rule: &AccessRule) -> String {
        match rule {
            AccessRule::Any { rules } => self.join(rules, "OR"),
            AccessRule::All { rules } => self.join(rules, "AND"),
            AccessRule::Not { rule } => format!("NOT ({})", self.expr(rule)),
            AccessRule::In {
                column,
                source:
                    MembershipSource::Rows {
                        table,
                        column: key,
                        filter,
                    },
            } => self.member(column, table, key, filter.as_deref()),
            AccessRule::Exists {
                source: MembershipSource::Rows { table, filter, .. },
            } => self.exists(table, filter.as_deref()),
            AccessRule::Owner { field } if owner_join(self.ast, self.model, field).is_some() => {
                self.owned_through(field)
            }
            _ => access_rule_to_expr(self.ast, self.model, rule, self.schema),
        }
    }

    /// Each rule parenthesised, so precedence is never left to chance.
    fn join(&mut self, rules: &[AccessRule], joiner: &str) -> String {
        let parts: Vec<String> = rules
            .iter()
            .map(|r| format!("({})", self.expr(r)))
            .collect();
        parts.join(&format!("\n    {joiner}\n    "))
    }

    /// `column` is one of the keys of `table`'s rows the caller may read. `COALESCE` keeps the
    /// answer for a NULL column false, as the `EXISTS` it replaces answered, so a `Not` around it
    /// means what it did.
    fn member(
        &mut self,
        column: &str,
        table: &str,
        key: &str,
        filter: Option<&AccessRule>,
    ) -> String {
        let filter =
            filter.map(|rule| rows_filter_sql(self.ast, self.model, table, rule, self.schema));
        let set = self.keys(table, key, filter.as_deref());
        let own = format!(
            "{}.{}",
            quote_ident(db_table_name(self.model)),
            quote_ident(column)
        );
        format!("COALESCE({own} IN (SELECT {set}), false)")
    }

    /// The caller may read at least one row of `table` that passes `filter`.
    fn exists(&mut self, table: &str, filter: Option<&AccessRule>) -> String {
        let source = quote_qualified(self.schema, table);
        let mut body = format!("SELECT EXISTS (SELECT 1 FROM {source}");
        if let Some(rule) = filter {
            let filter = rows_filter_sql(self.ast, self.model, table, rule, self.schema);
            body.push_str(&format!(" WHERE ({filter})"));
        }
        body.push(')');
        let set = self.register(RuleSet::new("boolean".to_string(), body));
        format!("(SELECT {set})")
    }

    /// `Owner` through a relation: the related row is one the caller owns.
    fn owned_through(&mut self, field: &str) -> String {
        let join = owner_join(self.ast, self.model, field).expect("checked by the caller");
        let table = quote_ident(&join.table);
        let mine = format!("{AUTH_UID} = {table}.{}", quote_ident(&join.owner_column));
        let set = self.keys(&join.table, "id", Some(&mine));
        let own = format!(
            "{}.{}",
            quote_ident(db_table_name(self.model)),
            quote_ident(&owner_column(self.model, field))
        );
        format!("COALESCE({own} IN (SELECT {set}), false)")
    }

    /// The helper returning `table.key` of every row of `table` the caller may read that passes
    /// `filter`, typed as the key column is.
    fn keys(&mut self, table: &str, key: &str, filter: Option<&str>) -> String {
        let source = quote_qualified(self.schema, table);
        let column = format!("{}.{}", quote_ident(table), quote_ident(key));
        let mut body = format!("SELECT {column} FROM {source}");
        if let Some(filter) = filter {
            body.push_str(&format!(" WHERE ({filter})"));
        }
        let returns = format!("SETOF {source}.{}%TYPE", quote_ident(key));
        self.register(RuleSet::new(returns, body))
    }

    /// Records `set` and returns its call.
    fn register(&mut self, set: RuleSet) -> String {
        let call = set.call();
        self.sets.entry(set.name.clone()).or_insert(set);
        call
    }
}

/// Whether `rule` reads a table other than the row's: only such a rule can be widened by the
/// Studio policies, so only it needs [`IN_RULE_SETTING`] around it.
pub fn reads_table(ast: &SchemaAst, model: &ModelAst, rule: &AccessRule) -> bool {
    match rule {
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter().any(|r| reads_table(ast, model, r))
        }
        AccessRule::Not { rule } => reads_table(ast, model, rule),
        AccessRule::In { source, .. } | AccessRule::Exists { source } => {
            matches!(source, MembershipSource::Rows { .. })
        }
        AccessRule::Owner { field } => owner_join(ast, model, field).is_some(),
        _ => false,
    }
}

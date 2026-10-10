//! Model-level `constraints` rendered as table `CHECK` expressions.
//!
//! A constraint is an access rule with a narrower operand set, so this reuses the node types rather
//! than defining a second grammar. What it does not reuse is the *renderer*: an access rule may read
//! `auth.uid()`, a claim or the clock, and a `CHECK` can do none of those. The CLI refuses those
//! nodes at push time, where the message can name the model and the constraint; this refuses them
//! again, because an AST can be written by hand and a constraint that silently rendered `TRUE` would
//! be worse than one that failed.
//!
//! **Measures arrive resolved.** `Length` and `ItemCount` carry the form the CLI worked out from the
//! field's kind, so nothing here has to know that a `JSONB` column might be an array or an object.
//! Deciding that twice is what produced `char_length(text[])`, and one copy of that table is enough.
use crate::parser::ast::{AccessRule, CompareOp, LiteralValue, MeasureForm, Operand};
use crate::sql_quote::{quote_ident, quote_literal};
use anyhow::{bail, Result};

/// The SQL that measures a column, per the form the CLI resolved.
pub fn measure_expr(column: &str, form: MeasureForm) -> String {
    let col = quote_ident(column);
    match form {
        MeasureForm::Chars => format!("char_length({col})"),
        MeasureForm::Octets => format!("octet_length({col})"),
        MeasureForm::RichText => format!("char_length(_supatype.richtext_text({col}))"),
        MeasureForm::Array => format!("cardinality({col})"),
        MeasureForm::JsonbArray => format!("jsonb_array_length({col})"),
    }
}

/// A measure over JSONB needs its type checked first, or it raises at insert instead of failing the
/// check. Returns the guard that must be ANDed in front of any comparison using this operand.
fn measure_guard(column: &str, form: MeasureForm) -> Option<String> {
    match form {
        MeasureForm::JsonbArray => Some(format!("jsonb_typeof({}) = 'array'", quote_ident(column))),
        _ => None,
    }
}

fn guards_for(operand: &Operand, out: &mut Vec<String>) {
    if let Operand::Length { column, form } | Operand::ItemCount { column, form } = operand {
        if let Some(guard) = measure_guard(column, *form) {
            if !out.contains(&guard) {
                out.push(guard);
            }
        }
    }
}

fn operand_expr(operand: &Operand) -> Result<String> {
    Ok(match operand {
        Operand::Column { name } => quote_ident(name),
        Operand::Literal { value } => literal_sql(value),
        Operand::Length { column, form } | Operand::ItemCount { column, form } => {
            measure_expr(column, *form)
        }
        // Everything else depends on the caller or the clock. The CLI names the model and the
        // constraint when it refuses these; this is the backstop for an AST that did not come
        // through it.
        other => bail!(
            "constraint operand {other:?} cannot be enforced by a CHECK: it depends on the caller \
             or the current time. Move the rule to `access`."
        ),
    })
}

fn compare_sql(op: &CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "=",
        CompareOp::Neq => "<>",
        CompareOp::Gt => ">",
        CompareOp::Gte => ">=",
        CompareOp::Lt => "<",
        CompareOp::Lte => "<=",
        CompareOp::Like => "LIKE",
    }
}

/// One constraint as a `CHECK` expression.
pub fn constraint_to_expr(rule: &AccessRule) -> Result<String> {
    match rule {
        AccessRule::Compare { left, op, right } => {
            let mut guards = Vec::new();
            guards_for(left, &mut guards);
            guards_for(right, &mut guards);
            let body = format!(
                "{} {} {}",
                operand_expr(left)?,
                compare_sql(op),
                operand_expr(right)?
            );
            Ok(if guards.is_empty() {
                body
            } else {
                format!("{} AND {body}", guards.join(" AND "))
            })
        }

        AccessRule::NullCheck { operand, is_null } => Ok(format!(
            "{} IS {}NULL",
            operand_expr(operand)?,
            if *is_null { "" } else { "NOT " }
        )),

        AccessRule::Matches { column, pattern } => Ok(format!(
            "{} ~ {}",
            quote_ident(column),
            quote_literal(pattern)
        )),

        AccessRule::Any { rules } | AccessRule::All { rules } => {
            if rules.is_empty() {
                bail!("an empty `Any<[]>` or `All<[]>` constrains nothing; remove it");
            }
            let joiner = if matches!(rule, AccessRule::Any { .. }) {
                " OR "
            } else {
                " AND "
            };
            let parts = rules
                .iter()
                .map(constraint_to_expr)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!(
                "({})",
                parts
                    .iter()
                    .map(|p| format!("({p})"))
                    .collect::<Vec<_>>()
                    .join(joiner)
            ))
        }

        AccessRule::Not { rule } => Ok(format!("NOT ({})", constraint_to_expr(rule)?)),

        other => bail!(
            "constraint rule {other:?} cannot be enforced by a CHECK. Rules about the caller belong \
             in `access`, which the API layer applies."
        ),
    }
}

fn literal_sql(value: &LiteralValue) -> String {
    match value {
        LiteralValue::Text(s) => quote_literal(s),
        LiteralValue::Number(n) => n.to_string(),
        LiteralValue::Bool(b) => b.to_string(),
    }
}

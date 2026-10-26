use super::accessors::db_foreign_key;
use super::ast::{AccessRule, FieldAst, MembershipSource, Operand, SchemaAst};
use anyhow::{bail, Result};
use std::collections::HashSet;

pub fn validate(mut ast: SchemaAst) -> Result<SchemaAst> {
    let model_names: std::collections::HashSet<String> =
        ast.models.iter().map(|m| m.name.clone()).collect();

    for model in &ast.models {
        if model.name.is_empty() {
            bail!("Model name cannot be empty");
        }
        if model.annotations.db.table_name.is_empty() {
            bail!("Model '{}' has an empty table name", model.name);
        }

        for (field_name, field) in &model.fields {
            if let FieldAst::Relation(rel) = field {
                if rel.is_owning()
                    && !model_names.contains(&rel.target)
                    && super::resolver::resolve_system_ref(&rel.target).is_none()
                {
                    bail!(
                        "Model '{}': field '{}' references unknown model '{}'. \
                         Did you rename the model and forget to update this relation?",
                        model.name,
                        field_name,
                        rel.target,
                    );
                }
            }
        }

        validate_operands(model)?;
        validate_vector_indexes(model)?;
    }

    // Over the whole schema at once: an `Owner` inside a membership filter is checked against
    // the model that filter reads, not the one the rule is attached to.
    super::owner_rules::validate(&mut ast)?;

    Ok(ast)
}

/// A `distance` belongs to an `hnsw` index, and an `hnsw` index to vector fields: pgvector's
/// operator classes are for its own type, and Postgres would otherwise refuse the index at push
/// time with a message that names no field.
fn validate_vector_indexes(model: &super::ast::ModelAst) -> Result<()> {
    use super::ast::IndexMethod;
    for index in model.indexes() {
        let hnsw = matches!(index.using, IndexMethod::Hnsw);
        if index.distance.is_some() && !hnsw {
            bail!(
                "Model '{}': the index on ({}) sets `distance`, which only an `hnsw` index uses.",
                model.name,
                index.fields.join(", ")
            );
        }
        // A key that names no field is left to the push, as for every other index: index keys
        // are not checked against the model anywhere yet (golden_tests.rs, `kitchen_sink`).
        let not_vector = index.fields.iter().find(|f| {
            model
                .fields
                .get(*f)
                .is_some_and(|field| !matches!(field, FieldAst::Vector(_)))
        });
        if let (true, Some(field)) = (hnsw, not_vector) {
            bail!(
                "Model '{}': the `hnsw` index on ({}) includes '{field}', which is not a Vector field.",
                model.name,
                index.fields.join(", ")
            );
        }
    }
    Ok(())
}

/// Collect relation FK column names for a model (db layer).
pub fn relation_fk_columns(model: &super::ast::ModelAst) -> HashSet<String> {
    let mut cols = HashSet::new();
    for (field_name, field) in &model.fields {
        if let FieldAst::Relation(rel) = field {
            if rel.is_owning() {
                cols.insert(
                    db_foreign_key(field, field_name).unwrap_or_else(|| {
                        super::accessors::default_foreign_key_column(field_name)
                    }),
                );
            }
        }
    }
    cols
}

/// Every rule attached to a model, so a check runs once against all of them rather than
/// being repeated per clause and quietly missing one.
///
/// `update_check` and the per-field rules are included deliberately: they are the two
/// that a walker written from memory forgets, and a rule that skips validation still
/// reaches Postgres.
fn model_access_rules(model: &super::ast::ModelAst) -> Vec<(&'static str, &AccessRule)> {
    let access = &model.annotations.platform.access;
    let mut rules: Vec<(&'static str, &AccessRule)> = Vec::new();
    for (clause, rule) in [
        ("read", &access.read),
        ("create", &access.create),
        ("update", &access.update),
        ("update check", &access.update_check),
        ("delete", &access.delete),
    ] {
        if let Some(rule) = rule {
            rules.push((clause, rule));
        }
    }
    for field in access.fields.values() {
        if let Some(rule) = &field.read {
            rules.push(("field read", rule));
        }
        if let Some(rule) = &field.write {
            rules.push(("field write", rule));
        }
    }
    rules
}

/// Apply `check` to every operand reachable from a rule, including inside a membership
/// source's filter, which is a rule in its own right and was where an earlier traversal
/// stopped short.
fn for_each_operand(
    rule: &AccessRule,
    check: &mut dyn FnMut(&Operand) -> Result<()>,
) -> Result<()> {
    match rule {
        AccessRule::Compare { left, right, .. } => {
            check(left)?;
            check(right)?;
        }
        AccessRule::NullCheck { operand, .. } => check(operand)?,
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            for inner in rules {
                for_each_operand(inner, check)?;
            }
        }
        AccessRule::Not { rule } => for_each_operand(rule, check)?,
        AccessRule::In { source, .. } | AccessRule::Exists { source } => {
            if let MembershipSource::Rows {
                filter: Some(filter),
                ..
            } = source
            {
                for_each_operand(filter, check)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// `After` / `Before` are the only operands that carry another operand, so they are the
/// only ones whose shape can be wrong rather than merely unsuitable.
///
/// Two things are refused here, and both would otherwise reach Postgres as SQL that is
/// valid and means something the author did not write.
///
/// A base that is not a time is the first. `now()` and `date_trunc(unit, now())` are the
/// only bases the renderer knows how to place, and a column or a claim would render as a
/// nested subquery whose meaning depends on the row. Refusing it here keeps the renderer's
/// fallback branch unreachable rather than load-bearing.
///
/// An all-zero interval is the second. It arrives as an empty object or as a misspelled
/// unit that deserialised to nothing, since the AST is read forward-compatibly and cannot
/// reject an unknown field without also rejecting every future one. `After<Now, {}>` and
/// `After<Now, { dayz: 30 }>` both mean `now()`, silently, and a policy that silently
/// means something else is the failure this catches.
fn validate_operand(model: &str, clause: &str, operand: &Operand) -> Result<()> {
    let (name, base, interval) = match operand {
        Operand::After { base, interval } => ("After", base, interval),
        Operand::Before { base, interval } => ("Before", base, interval),
        _ => return Ok(()),
    };

    if !matches!(**base, Operand::Now | Operand::StartOf { .. }) {
        bail!(
            "Model '{model}': the {clause} rule uses `{name}` with a base that is not a time. \
             Its base must be `Now` or `StartOf<unit>`; `{:?}` depends on the row or the caller \
             and cannot be offset.",
            base
        );
    }

    if interval.is_zero() {
        bail!(
            "Model '{model}': the {clause} rule uses `{name}` with an empty interval, which \
             means the base unchanged. Give at least one of years, months, weeks, days, hours, \
             minutes or seconds, and check the spelling: an unrecognised unit is read as absent \
             rather than refused, so `{{ dayz: 30 }}` arrives here as nothing at all."
        );
    }

    // Nested: `After<After<Now, ...>, ...>` is refused by the base check above, so this is
    // only reached for a base that is already `Now` or `StartOf`, which carry no operand.
    Ok(())
}

/// Check every operand in every rule on a model.
fn validate_operands(model: &super::ast::ModelAst) -> Result<()> {
    for (clause, rule) in model_access_rules(model) {
        for_each_operand(rule, &mut |operand| {
            validate_operand(&model.name, clause, operand)
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod operand_validation_tests {
    use super::*;
    use crate::parser::ast::{CompareOp, IntervalSpec, ModelAst, TruncUnit};

    fn model_with_read(rule: AccessRule) -> ModelAst {
        let mut model = ModelAst {
            name: "Event".to_string(),
            fields: indexmap::IndexMap::new(),
            options: Default::default(),
            annotations: Default::default(),
        };
        model.annotations.db.table_name = "event".to_string();
        model.annotations.platform.access.read = Some(rule);
        model
    }

    fn compare_against(right: Operand) -> AccessRule {
        AccessRule::Compare {
            left: Operand::Column {
                name: "starts_at".to_string(),
            },
            op: CompareOp::Lte,
            right,
        }
    }

    fn after(base: Operand, interval: IntervalSpec) -> Operand {
        Operand::After {
            base: Box::new(base),
            interval,
        }
    }

    #[test]
    fn accepts_a_now_base() {
        let rule = compare_against(after(
            Operand::Now,
            IntervalSpec {
                days: 30,
                ..IntervalSpec::default()
            },
        ));
        assert!(validate_operands(&model_with_read(rule)).is_ok());
    }

    #[test]
    fn accepts_a_truncation_base() {
        let rule = compare_against(after(
            Operand::StartOf {
                unit: TruncUnit::Day,
            },
            IntervalSpec {
                days: 30,
                hours: 9,
                ..IntervalSpec::default()
            },
        ));
        assert!(validate_operands(&model_with_read(rule)).is_ok());
    }

    // A column base would render as a nested subquery whose meaning depends on the row.
    #[test]
    fn refuses_a_column_base() {
        let rule = compare_against(after(
            Operand::Column {
                name: "created_at".to_string(),
            },
            IntervalSpec {
                days: 1,
                ..IntervalSpec::default()
            },
        ));
        let error = validate_operands(&model_with_read(rule))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Event"),
            "error must name the model: {error}"
        );
        assert!(
            error.contains("read"),
            "error must name the clause: {error}"
        );
        assert!(
            error.contains("Now") && error.contains("StartOf"),
            "error must say what a valid base is: {error}"
        );
    }

    #[test]
    fn refuses_a_caller_base() {
        let rule = compare_against(after(
            Operand::AuthUid,
            IntervalSpec {
                days: 1,
                ..IntervalSpec::default()
            },
        ));
        assert!(validate_operands(&model_with_read(rule)).is_err());
    }

    // An empty spec means the base unchanged, which is never what an author wrote.
    #[test]
    fn refuses_an_empty_interval() {
        let rule = compare_against(after(Operand::Now, IntervalSpec::default()));
        let error = validate_operands(&model_with_read(rule))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("empty interval"),
            "error must say the interval is empty: {error}"
        );
        assert!(
            error.contains("spelling"),
            "error must mention the misspelled-unit case, which is how this usually arrives: {error}"
        );
    }

    // A misspelled unit deserialises to all zeroes, because the AST is read
    // forward-compatibly. This is the case the empty check exists for, reached through
    // serde rather than constructed.
    #[test]
    fn a_misspelled_unit_is_caught_as_an_empty_interval() {
        let spec: IntervalSpec =
            serde_json::from_str(r#"{"dayz": 30}"#).expect("unknown fields are ignored");
        assert!(spec.is_zero());
        let rule = compare_against(after(Operand::Now, spec));
        assert!(validate_operands(&model_with_read(rule)).is_err());
    }

    // Negative components are refused by the type, not by a check: `IntervalSpec` holds
    // `u32`, so serde stops a negative before validation is reached. Pinned because the
    // guarantee is load-bearing and invisible: direction lives in the operand name, and
    // a signed component would quietly reintroduce the double negative `Ago`/`FromNow`
    // were designed to avoid. The CLI is where an author sees the helpful message.
    #[test]
    fn a_negative_component_is_refused_by_deserialisation() {
        let error = serde_json::from_str::<IntervalSpec>(r#"{"days": -5}"#)
            .expect_err("a negative component must not deserialise");
        assert!(
            error.to_string().contains("invalid value") || error.to_string().contains("-5"),
            "unexpected error: {error}"
        );
    }

    // Round trip: what the CLI emits is what the engine reads.
    #[test]
    fn an_interval_round_trips_through_serde() {
        let spec = IntervalSpec {
            days: 30,
            hours: 9,
            ..IntervalSpec::default()
        };
        let json = serde_json::to_string(&spec).expect("serialises");
        let back: IntervalSpec = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(spec, back);

        // And the partial form the CLI actually writes, with absent units omitted.
        let partial: IntervalSpec =
            serde_json::from_str(r#"{"days": 30, "hours": 9}"#).expect("partial deserialises");
        assert_eq!(partial, spec);
    }

    #[test]
    fn refuses_a_before_with_a_bad_base() {
        let rule = compare_against(Operand::Before {
            base: Box::new(Operand::Column {
                name: "x".to_string(),
            }),
            interval: IntervalSpec {
                days: 1,
                ..IntervalSpec::default()
            },
        });
        assert!(validate_operands(&model_with_read(rule)).is_err());
    }

    // The traversal has to reach operands nested in compositions and in a membership
    // source's filter. A walker that stops at the top level lets a bad rule through.
    #[test]
    fn reaches_an_operand_nested_in_a_composition() {
        let bad = compare_against(after(Operand::AuthUid, IntervalSpec::default()));
        let rule = AccessRule::Any {
            rules: vec![
                AccessRule::Public,
                AccessRule::All {
                    rules: vec![AccessRule::Not {
                        rule: Box::new(bad),
                    }],
                },
            ],
        };
        assert!(validate_operands(&model_with_read(rule)).is_err());
    }

    #[test]
    fn reaches_an_operand_inside_a_membership_filter() {
        let bad = compare_against(after(Operand::AuthUid, IntervalSpec::default()));
        let rule = AccessRule::In {
            column: "organiser_id".to_string(),
            source: MembershipSource::Rows {
                table: "organiser".to_string(),
                column: "id".to_string(),
                filter: Some(Box::new(bad)),
            },
        };
        assert!(validate_operands(&model_with_read(rule)).is_err());
    }

    // Every clause is walked, not just `read`. `update_check` and the per-field rules
    // are the two a walker written from memory forgets.
    #[test]
    fn walks_update_check_and_field_rules() {
        let bad = compare_against(after(Operand::AuthUid, IntervalSpec::default()));

        let mut update_check_model = model_with_read(AccessRule::Public);
        update_check_model.annotations.platform.access.update_check = Some(bad.clone());
        assert!(
            validate_operands(&update_check_model).is_err(),
            "update_check was not walked"
        );

        let mut field_model = model_with_read(AccessRule::Public);
        field_model.annotations.platform.access.fields.insert(
            "starts_at".to_string(),
            crate::parser::ast::FieldAccessAst {
                read: None,
                write: Some(bad),
            },
        );
        assert!(
            validate_operands(&field_model).is_err(),
            "per-field rules were not walked"
        );
    }
}

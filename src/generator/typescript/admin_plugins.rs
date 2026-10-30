//! What Studio needs to render a plugin's editors, in the admin config.
//!
//! A `custom` field is edited with its field type's widget, and a plugin composite's columns are
//! shown together under the composite's widget. Both are additions to the admin config: a field's
//! `widget` stays the built-in editor for its Postgres type, so a Studio that predates plugin
//! widgets, or one that cannot load this plugin's, still has an editor for every column.

use crate::parser::accessors::field_annotations;
use crate::parser::annotations::CompositeMembership;
use crate::parser::ast::{FieldAst, ModelAst};
use serde_json::{json, Value};

/// `{ plugin, fieldType }` for a plugin-defined field, `None` for any other. Studio looks the
/// plugin's editor up by the field type: a field type plugin ships one editor, for its own type.
pub fn plugin_field(field: &FieldAst) -> Option<Value> {
    let FieldAst::Custom(custom) = field else {
        return None;
    };
    Some(json!({
        "plugin": custom.plugin,
        "fieldType": custom.field_type,
    }))
}

/// Adds `compositeGroups` to the model's config when it uses a plugin composite. Left out
/// otherwise, so a schema without plugins produces the admin config it always did.
pub fn add_composite_groups(config: &mut Value, model: &ModelAst) {
    let groups = composite_groups(model);
    if !groups.is_empty() {
        config["compositeGroups"] = Value::Array(groups);
    }
}

/// One entry per plugin composite the model uses, its columns in declaration order. Studio looks
/// the composite's editor up by its name, as for a field type.
fn composite_groups(model: &ModelAst) -> Vec<Value> {
    let mut groups: Vec<(CompositeMembership, Vec<String>)> = Vec::new();
    for (name, field) in &model.fields {
        let Some(member) = field_annotations(field).platform.composite.as_ref() else {
            continue;
        };
        let same = |(m, _): &&mut (CompositeMembership, Vec<String>)| {
            m.plugin == member.plugin && m.name == member.name
        };
        match groups.iter_mut().find(same) {
            Some((_, columns)) => columns.push(name.clone()),
            None => groups.push((member.clone(), vec![name.clone()])),
        }
    }
    groups.into_iter().map(group_json).collect()
}

fn group_json((member, fields): (CompositeMembership, Vec<String>)) -> Value {
    json!({
        "plugin": member.plugin,
        "composite": member.name,
        "label": member.label,
        "collapsible": member.collapsible,
        "defaultCollapsed": member.default_collapsed,
        "fields": fields,
    })
}

use super::annotations::{DbFieldAnnotations, FieldAnnotations, ModelAnnotations};
use super::ast::{
    scalar_of, ArrayFieldAst, BlockDefinitionAst, BlocksFieldAst, CustomFieldAst, DecimalFieldAst,
    DefaultValueAst, EnumFieldAst, FieldAst, GeneratedColumnAst, GeoFieldAst, IdentityGeneration,
    JsonFieldAst, ModelAst, ModelOptions, RelationCardinality, RelationFieldAst, ScalarFieldAst,
    SchemaAst, SlugFieldAst, StorageAccessMode, StorageFieldAst, ValidationAst, VectorFieldAst,
};
use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

pub fn deserialize_schema(value: &Value) -> Result<SchemaAst> {
    let ast_version = value
        .get("astVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if ast_version != 2 {
        bail!(
            "Schema AST must have \"astVersion\": 2 (got {ast_version}). \
             Flat v1 AST is no longer accepted."
        );
    }

    let models_val = value
        .get("models")
        .context("Schema AST missing \"models\"")?;
    let models_arr = models_val
        .as_array()
        .context("\"models\" must be an array")?;

    let mut models = Vec::with_capacity(models_arr.len());
    for model_val in models_arr {
        models.push(deserialize_model(model_val)?);
    }

    Ok(SchemaAst {
        ast_version: 2,
        models,
        junction_tables: deserialize_optional_vec(value, "junctionTables")?,
        storage_buckets: deserialize_optional_vec(value, "storageBuckets")?,
        locales: deserialize_optional_string_vec(value, "locales"),
        default_locale: value
            .get("defaultLocale")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        plugins: deserialize_optional_vec(value, "plugins")?,
        sso: value
            .get("sso")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?,
        publishing: value
            .get("publishing")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?,
        warnings: deserialize_optional_string_vec(value, "warnings"),
        rename_journal: deserialize_optional_vec(value, "renameJournal")?,
        recorded_names: Default::default(),
    })
}

fn deserialize_optional_vec<T: for<'de> Deserialize<'de>>(
    value: &Value,
    key: &str,
) -> Result<Vec<T>> {
    match value.get(key) {
        None => Ok(Vec::new()),
        Some(v) => Ok(serde_json::from_value(v.clone())?),
    }
}

fn deserialize_optional_string_vec(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

fn deserialize_model(value: &Value) -> Result<ModelAst> {
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .context("model missing \"name\"")?
        .to_string();

    let fields_val = value.get("fields").context("model missing \"fields\"")?;
    let fields_obj = fields_val
        .as_object()
        .context("\"fields\" must be an object")?;
    let mut fields = IndexMap::new();
    for (field_name, field_val) in fields_obj {
        fields.insert(
            field_name.clone(),
            deserialize_field(field_val)
                .with_context(|| format!("model {name}, field \"{field_name}\""))?,
        );
    }

    let options: ModelOptions = value
        .get("options")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();

    let annotations: ModelAnnotations = value
        .get("annotations")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();

    Ok(ModelAst {
        name,
        fields,
        options,
        annotations,
    })
}

/// The `check` a field carries, if its variant has anywhere to put one.
///
/// Nine of twelve variants had no `check` field, so serde discarded declared constraints without a
/// word and the column was created unconstrained. {@link deserialize_field} uses this to refuse the
/// AST instead, which is what stops a new field kind regressing into the same silence.
fn carried_check(field: &FieldAst) -> Option<&str> {
    match field {
        FieldAst::Slug(f) => f.check.as_deref(),
        FieldAst::Decimal(f) => f.check.as_deref(),
        FieldAst::Json(f) | FieldAst::Button(f) => f.check.as_deref(),
        FieldAst::Array(f) => f.check.as_deref(),
        FieldAst::Blocks(f) => f.check.as_deref(),
        FieldAst::Custom(f) => f.check.as_deref(),
        other => scalar_of(other).and_then(|f| f.check.as_deref()),
    }
}

fn deserialize_field(value: &Value) -> Result<FieldAst> {
    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .context("field missing \"kind\"")?;

    let annotations: FieldAnnotations = value
        .get("annotations")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();

    let required = value
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let read_only = annotations.platform.read_only;
    let localized = value
        .get("localized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Enums carry their default as a bare String on EnumFieldAst rather than a DefaultValueAst,
    // so the structured value is not what that branch wants. It reads it through
    // `enum_default_literal` instead.
    let default_val: Option<DefaultValueAst> = if kind == "enum" {
        None
    } else {
        value
            .get("default")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?
    };

    let parsed: Result<FieldAst> = match kind {
        "text" => Ok(FieldAst::Text(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "richText" => Ok(FieldAst::RichText(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "integer" => Ok(FieldAst::Integer(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "smallInt" => Ok(FieldAst::SmallInt(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "bigInt" => Ok(FieldAst::BigInt(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "float" => Ok(FieldAst::Float(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "boolean" => Ok(FieldAst::Boolean(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "datetime" => Ok(FieldAst::Datetime(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "date" => Ok(FieldAst::Date(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "timestamp" => Ok(FieldAst::Timestamp(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "uuid" => Ok(FieldAst::Uuid(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "email" => Ok(FieldAst::Email(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "url" => Ok(FieldAst::Url(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "bytes" => Ok(FieldAst::Bytes(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "serial" => Ok(FieldAst::Serial(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "bigSerial" => Ok(FieldAst::BigSerial(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "money" => Ok(FieldAst::Money(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "ip" => Ok(FieldAst::Ip(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "cidr" => Ok(FieldAst::Cidr(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "macaddr" => Ok(FieldAst::Macaddr(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "interval" => Ok(FieldAst::Interval(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "tsQuery" => Ok(FieldAst::TsQuery(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "tsVector" => Ok(FieldAst::TsVector(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "xml" => Ok(FieldAst::Xml(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "color" => Ok(FieldAst::Color(scalar_from_v2(
            &annotations,
            required,
            value,
            read_only,
            localized,
            default_val,
        )?)),
        "json" => {
            let pg_type = pg_type_or_default(&annotations.db, kind);
            Ok(FieldAst::Json(JsonFieldAst {
                pg_type,
                required,
                check: check_from_v2(value),
                validation: validation_from_v2(value),
                localized,
                read_only,
                ts_type: value
                    .get("tsType")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                annotations: annotations.clone(),
            }))
        }
        "button" => {
            let pg_type = pg_type_or_default(&annotations.db, kind);
            Ok(FieldAst::Button(JsonFieldAst {
                pg_type,
                required,
                check: check_from_v2(value),
                validation: validation_from_v2(value),
                localized,
                read_only,
                ts_type: None,
                annotations: annotations.clone(),
            }))
        }
        "slug" => {
            let from = value
                .get("from")
                .and_then(|v| v.as_str())
                .context("slug field missing \"from\"")?
                .to_string();
            let pg_type = pg_type_or_default(&annotations.db, kind);
            Ok(FieldAst::Slug(SlugFieldAst {
                pg_type,
                required,
                unique: annotations.db.unique,
                from,
                check: check_from_v2(value),
                validation: validation_from_v2(value),
                localized,
                read_only,
                annotations,
            }))
        }
        "enum" => {
            let values: Vec<String> = value
                .get("values")
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()?
                .unwrap_or_default();
            let enum_default = value.get("default").and_then(enum_default_literal);
            let pg_type = pg_type_or_default(&annotations.db, kind);
            Ok(FieldAst::Enum(EnumFieldAst {
                pg_type,
                values,
                required,
                unique: annotations.db.unique,
                default: enum_default,
                localized,
                read_only,
                annotations,
            }))
        }
        "decimal" => {
            let pg_type = pg_type_or_default(&annotations.db, kind);
            Ok(FieldAst::Decimal(DecimalFieldAst {
                pg_type,
                required,
                precision: value
                    .get("precision")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32),
                scale: value
                    .get("scale")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32),
                check: check_from_v2(value),
                validation: validation_from_v2(value),
                localized,
                read_only,
                annotations,
            }))
        }
        "array" => {
            let element_type = annotations
                .db
                .element_type
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "TEXT".to_string());
            Ok(FieldAst::Array(ArrayFieldAst {
                check: check_from_v2(value),
                validation: validation_from_v2(value),
                element_type,
                required,
                unique: annotations.db.unique,
                default: default_val,
                read_only,
                annotations,
            }))
        }
        "image" | "file" => {
            let bucket = value
                .get("bucket")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let access_mode = value.get("accessMode").and_then(|v| match v.as_str() {
                Some("public") => Some(StorageAccessMode::Public),
                Some("private") => Some(StorageAccessMode::Private),
                Some("custom") => Some(StorageAccessMode::Custom),
                _ => None,
            });
            let pg_type = pg_type_or_default(&annotations.db, kind);
            let storage = StorageFieldAst {
                pg_type,
                required,
                bucket,
                access_mode,
                read_only,
                localized,
                annotations,
            };
            if kind == "image" {
                Ok(FieldAst::Image(storage))
            } else {
                Ok(FieldAst::File(storage))
            }
        }
        "geo" => {
            let pg_type = pg_type_or_default(&annotations.db, kind);
            Ok(FieldAst::Geo(GeoFieldAst {
                pg_type,
                required,
                geo_type: value
                    .get("geoType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("point")
                    .to_string(),
                srid: value.get("srid").and_then(|v| v.as_u64()).map(|n| n as u32),
                read_only,
                annotations,
            }))
        }
        "vector" => Ok(FieldAst::Vector(VectorFieldAst {
            pg_type: pg_type_or_default(&annotations.db, kind),
            required,
            dimensions: value
                .get("dimensions")
                .and_then(|v| v.as_u64())
                .unwrap_or(1536) as u32,
            read_only,
            annotations,
        })),
        "blocks" => {
            let blocks: Vec<BlockDefinitionAst> = value
                .get("blocks")
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()?
                .unwrap_or_default();
            Ok(FieldAst::Blocks(BlocksFieldAst {
                check: check_from_v2(value),
                validation: validation_from_v2(value),
                required,
                blocks,
                index: value.get("index").and_then(|v| v.as_bool()).unwrap_or(true),
                read_only,
                localized,
                annotations,
            }))
        }
        "relation" => {
            let cardinality: RelationCardinality = value
                .get("cardinality")
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()?
                .unwrap_or(RelationCardinality::BelongsTo);
            let target = value
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            Ok(FieldAst::Relation(RelationFieldAst {
                cardinality,
                target,
                foreign_key: annotations.db.foreign_key.clone(),
                references: value
                    .get("references")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                through: value
                    .get("through")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                on_delete: value
                    .get("onDelete")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                on_update: value
                    .get("onUpdate")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                unique_fk: value
                    .get("uniqueFk")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                required,
                read_only,
                annotations,
            }))
        }
        "custom" => Ok(FieldAst::Custom(custom_from_v2(
            &annotations,
            required,
            value,
            read_only,
        )?)),
        "timestamps" => Ok(FieldAst::Timestamps),
        "publishable" => Ok(FieldAst::Publishable),
        "softDelete" => Ok(FieldAst::SoftDelete),
        other => bail!("Unknown field kind: {other}"),
    };
    let field = parsed?;

    // A `check` the chosen variant cannot hold would be dropped by serde in silence, which is
    // exactly how nine field kinds came to accept a declared bound and enforce nothing. Refuse the
    // AST instead: a push that fails is recoverable, a constraint that quietly never existed is not.
    if value.get("check").is_some() && carried_check(&field).is_none() {
        bail!(
            "field of kind '{kind}' carries a check constraint, but that kind has nowhere to store one. Either add `check` to its AST struct and render it, or refuse the bound in the CLI's field-bounds table."
        );
    }

    // The same for `identity` and `generated`: only a scalar column renders them.
    let declares = |key: &str| value.get(key).is_some_and(|v| !v.is_null());
    let generates = matches!(field, FieldAst::Serial(_) | FieldAst::BigSerial(_))
        || scalar_of(&field).is_none();
    if (declares("identity") || declares("generated") || declares("autoIncrement")) && generates {
        bail!(
            "a field of kind '{kind}' cannot be an identity or generated column: only a scalar \
             column (text, a number, a date, ...) can be generated, and only an integer one can be \
             an identity"
        );
    }

    Ok(field)
}

fn scalar_from_v2(
    annotations: &FieldAnnotations,
    required: bool,
    value: &Value,
    read_only: bool,
    localized: bool,
    default_val: Option<DefaultValueAst>,
) -> Result<ScalarFieldAst> {
    let kind = value.get("kind").and_then(|v| v.as_str()).unwrap_or("text");
    let pg_type = pg_type_or_default(&annotations.db, kind);
    let sources: Vec<String> = value
        .get("sources")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();
    let template = value
        .get("template")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let (identity, generated) = column_generation_from_v2(value, kind, &default_val, localized)?;
    let auto_increment = value
        .get("autoIncrement")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if auto_increment && identity != Some(IdentityGeneration::ByDefault) {
        bail!("\"autoIncrement\" is an identity column generated by default: it needs \"identity\": \"byDefault\"");
    }
    // Postgres makes an identity column NOT NULL whatever the declaration says.
    let required = required || identity.is_some();
    Ok(ScalarFieldAst {
        pg_type,
        required,
        unique: annotations.db.unique,
        primary_key: value
            .get("primaryKey")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        index: annotations.db.index,
        default: default_val,
        check: check_from_v2(value),
        validation: validation_from_v2(value),
        localized,
        read_only,
        sources,
        template,
        identity,
        auto_increment,
        generated,
        annotations: annotations.clone(),
    })
}

/// The kinds an identity column can have: Postgres numbers only integer columns.
const IDENTITY_KINDS: [&str; 3] = ["integer", "smallInt", "bigInt"];

/// A field's `identity` and `generated` (identity-contract): read, and refused where Postgres
/// would refuse them or where the engine would otherwise drop them without a word.
fn column_generation_from_v2(
    value: &Value,
    kind: &str,
    default_val: &Option<DefaultValueAst>,
    localized: bool,
) -> Result<(Option<IdentityGeneration>, Option<GeneratedColumnAst>)> {
    let identity: Option<IdentityGeneration> = value
        .get("identity")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .context("\"identity\" must be \"always\" or \"byDefault\"")?;
    let generated: Option<GeneratedColumnAst> = value
        .get("generated")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .context("\"generated\" must be { \"expression\": string, \"stored\": true }")?;
    if identity.is_some() && !IDENTITY_KINDS.contains(&kind) {
        bail!("an identity column must be an integer (integer, smallInt or bigInt), not {kind}");
    }
    if identity.is_some() && generated.is_some() {
        bail!("a column is either an identity column or a generated one, not both");
    }
    if let Some(g) = &generated {
        if !g.stored {
            bail!("only stored generated columns are supported (\"stored\": true)");
        }
        if g.expression.trim().is_empty() {
            bail!("a generated column needs an expression");
        }
    }
    if (identity.is_some() || generated.is_some()) && default_val.is_some() {
        bail!("an identity or generated column cannot also have a default");
    }
    if (identity.is_some() || generated.is_some()) && localized {
        bail!("an identity or generated column cannot be localized");
    }
    Ok((identity, generated))
}

/// The raw `check` expression a field carries, still holding the `{name}` placeholder.
fn check_from_v2(value: &Value) -> Option<String> {
    value
        .get("check")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Structured constraint bounds, absent when the field declares no constraint modifier.
///
/// Returned as `None` rather than an empty struct so the admin config and any re-serialised AST stay
/// free of `"validation": {}` noise on the overwhelming majority of fields that have no bounds.
fn validation_from_v2(value: &Value) -> Option<ValidationAst> {
    let raw = value.get("validation")?;
    let parsed: ValidationAst = serde_json::from_value(raw.clone()).ok()?;
    if parsed.is_empty() {
        return None;
    }
    Some(parsed)
}

fn custom_from_v2(
    annotations: &FieldAnnotations,
    required: bool,
    value: &Value,
    read_only: bool,
) -> Result<CustomFieldAst> {
    let default_val: Option<DefaultValueAst> = value
        .get("default")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?;
    Ok(CustomFieldAst {
        plugin: custom_key(value, "plugin")?,
        field_type: custom_key(value, "fieldType")?,
        pg_type: pg_type_or_default(&annotations.db, "custom"),
        ts_type: custom_key(value, "tsType")?,
        required,
        unique: annotations.db.unique,
        index: annotations.db.index,
        default: default_val,
        read_only,
        annotations: annotations.clone(),
        check: value
            .get("check")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// A string a custom field must carry, or the error naming the one it lacks.
fn custom_key(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .with_context(|| format!("custom field missing \"{key}\""))
}

/// The literal behind an enum field's `default`, or None when there is not one.
///
/// Every default reaches this parser as an object, `{"kind":"value","value":"user"}`. This used to
/// call `.as_str()` on that object, which is None for anything but a bare string, so an enum's
/// default was silently discarded on every schema.
///
/// The damage landed in the generated types rather than the database. `field_has_default` handles
/// `FieldAst::Enum` correctly and was simply never told there was one, so
/// `Default<"user" | "editor" | "admin", "user">` was emitted as **required** in `Insert` while
/// `Default<Int, 0>` on the same model was optional. Callers were made to pass a value the
/// database would have filled in.
///
/// The bare-string arm is kept for an AST written before defaults were structured.
fn enum_default_literal(raw: &serde_json::Value) -> Option<String> {
    if let Some(s) = raw.as_str() {
        return Some(s.to_string());
    }
    match serde_json::from_value::<DefaultValueAst>(raw.clone()).ok()? {
        DefaultValueAst::Value { value } => value.as_str().map(str::to_string),
        // An enum column defaults to one of its own members. An expression or a generated value is
        // not one, and `EnumFieldAst::default` is a String with nowhere to record the difference.
        _ => None,
    }
}

fn pg_type_or_default(db: &DbFieldAnnotations, kind: &str) -> String {
    if !db.pg_type.is_empty() {
        return db.pg_type.clone();
    }
    default_pg_type(kind).to_string()
}

pub fn default_pg_type(kind: &str) -> &'static str {
    match kind {
        "text" | "email" | "url" | "slug" | "color" | "enum" => "TEXT",
        // Each of these is its own Postgres type, and each sat in the TEXT arm above beside `email`
        // and `url`. The columns were always right, because the DDL comes from the field variant.
        // What was wrong is what the AST told anyone reading it, and the AST is a published
        // contract: a consumer read TEXT, wrote a parser that rejected every value the column
        // returns, and cast to the wrong type. Studio publishes this field too.
        //
        // Found by pushing one model carrying every field kind and comparing the AST against
        // `information_schema`, which is what the conformance harness does.
        "ip" => "INET",
        "cidr" => "CIDR",
        "macaddr" => "MACADDR",
        "xml" => "XML",
        "tsQuery" => "TSQUERY",
        "tsVector" => "TSVECTOR",
        // Matches the DDL the differ emits, which has always been NUMERIC(19,4). `money` sat in
        // the TEXT arm above beside `email` and `url`, so the column was numeric while every
        // consumer of the AST was told it was text. `decimal` below was already right, which is
        // what made this look deliberate.
        //
        // The AST is a published contract, and someone acted on it: read TEXT, wrote a parser that
        // rejected every value the column returns, and cast to the wrong type. Studio publishes
        // this field too, so it was showing the same thing.
        "money" => "NUMERIC(19,4)",
        "richText" | "json" | "button" | "image" | "file" | "blocks" => "JSONB",
        "integer" => "INTEGER",
        "smallInt" => "SMALLINT",
        "bigInt" => "BIGINT",
        "float" => "DOUBLE PRECISION",
        "boolean" => "BOOLEAN",
        "datetime" => "TIMESTAMPTZ",
        "date" => "DATE",
        "timestamp" => "TIMESTAMP",
        "uuid" => "UUID",
        "bytes" => "BYTEA",
        "serial" => "SERIAL",
        "bigSerial" => "BIGSERIAL",
        "decimal" => "NUMERIC",
        "geo" => "GEOGRAPHY",
        "vector" => "VECTOR",
        "array" => "ARRAY",
        _ => "TEXT",
    }
}

/// Serialize schema AST back to v2 wire format (snapshots, tests).
pub fn serialize_schema(ast: &SchemaAst) -> Value {
    let models: Vec<Value> = ast.models.iter().map(serialize_model).collect();
    let mut root = serde_json::json!({
        "astVersion": ast.ast_version,
        "models": models,
    });
    if !ast.junction_tables.is_empty() {
        root["junctionTables"] = serde_json::to_value(&ast.junction_tables).unwrap_or(Value::Null);
    }
    if !ast.storage_buckets.is_empty() {
        root["storageBuckets"] = serde_json::to_value(&ast.storage_buckets).unwrap_or(Value::Null);
    }
    if !ast.locales.is_empty() {
        root["locales"] = serde_json::to_value(&ast.locales).unwrap_or(Value::Null);
    }
    if let Some(ref dl) = ast.default_locale {
        root["defaultLocale"] = Value::String(dl.clone());
    }
    if !ast.plugins.is_empty() {
        root["plugins"] = serde_json::to_value(&ast.plugins).unwrap_or(Value::Null);
    }
    if let Some(ref sso) = ast.sso {
        root["sso"] = serde_json::to_value(sso).unwrap_or(Value::Null);
    }
    if let Some(ref publishing) = ast.publishing {
        root["publishing"] = serde_json::to_value(publishing).unwrap_or(Value::Null);
    }
    if !ast.warnings.is_empty() {
        root["warnings"] = serde_json::to_value(&ast.warnings).unwrap_or(Value::Null);
    }
    if !ast.rename_journal.is_empty() {
        root["renameJournal"] = serde_json::to_value(&ast.rename_journal).unwrap_or(Value::Null);
    }
    root
}

fn serialize_model(model: &ModelAst) -> Value {
    let mut fields = serde_json::Map::new();
    for (name, field) in &model.fields {
        fields.insert(name.clone(), serialize_field(field));
    }
    serde_json::json!({
        "name": model.name,
        "fields": Value::Object(fields),
        "options": model.options,
        "annotations": model.annotations,
    })
}

fn serialize_field(field: &FieldAst) -> Value {
    match field {
        FieldAst::Text(s) => scalar_to_v2("text", s),
        FieldAst::RichText(s) => scalar_to_v2("richText", s),
        FieldAst::Integer(s) => scalar_to_v2("integer", s),
        FieldAst::Float(s) => scalar_to_v2("float", s),
        FieldAst::Boolean(s) => scalar_to_v2("boolean", s),
        FieldAst::Datetime(s) => scalar_to_v2("datetime", s),
        FieldAst::Uuid(s) => scalar_to_v2("uuid", s),
        FieldAst::Email(s) => scalar_to_v2("email", s),
        FieldAst::BigInt(s) => scalar_to_v2("bigInt", s),
        FieldAst::Bytes(s) => scalar_to_v2("bytes", s),
        FieldAst::SmallInt(s) => scalar_to_v2("smallInt", s),
        FieldAst::Date(s) => scalar_to_v2("date", s),
        FieldAst::Timestamp(s) => scalar_to_v2("timestamp", s),
        FieldAst::Serial(s) => scalar_to_v2("serial", s),
        FieldAst::BigSerial(s) => scalar_to_v2("bigSerial", s),
        FieldAst::Money(s) => scalar_to_v2("money", s),
        FieldAst::Url(s) => scalar_to_v2("url", s),
        FieldAst::Ip(s) => scalar_to_v2("ip", s),
        FieldAst::Cidr(s) => scalar_to_v2("cidr", s),
        FieldAst::Macaddr(s) => scalar_to_v2("macaddr", s),
        FieldAst::Interval(s) => scalar_to_v2("interval", s),
        FieldAst::TsQuery(s) => scalar_to_v2("tsQuery", s),
        FieldAst::TsVector(s) => scalar_to_v2("tsVector", s),
        FieldAst::Xml(s) => scalar_to_v2("xml", s),
        FieldAst::Color(s) => scalar_to_v2("color", s),
        FieldAst::Slug(s) => {
            let mut v = serde_json::json!({
                "kind": "slug",
                "required": s.required,
                "from": s.from,
                "annotations": slug_field_annotations(s),
            });
            if s.localized {
                v["localized"] = Value::Bool(true);
            }
            v
        }
        FieldAst::Enum(e) => {
            let mut v = serde_json::json!({
                "kind": "enum",
                "values": e.values,
                "required": e.required,
                "annotations": enum_field_annotations(e),
            });
            if let Some(ref d) = e.default {
                v["default"] = Value::String(d.clone());
            }
            v
        }
        // `localized` and `tsType` round-trip like every other kind's: dropping them wrote a
        // localized JSON column back as a plain one, and its declared shape back as any JSON.
        FieldAst::Json(j) => {
            let mut v = serde_json::json!({
                "kind": "json",
                "required": j.required,
                "annotations": j.annotations,
            });
            if j.localized {
                v["localized"] = Value::Bool(true);
            }
            if let Some(ts_type) = &j.ts_type {
                v["tsType"] = Value::String(ts_type.clone());
            }
            v
        }
        FieldAst::Button(b) => {
            let mut v = serde_json::json!({
                "kind": "button",
                "required": b.required,
                "annotations": b.annotations,
            });
            if b.localized {
                v["localized"] = Value::Bool(true);
            }
            v
        }
        FieldAst::Decimal(d) => serde_json::json!({
            "kind": "decimal",
            "required": d.required,
            "annotations": d.annotations,
        }),
        FieldAst::Array(a) => serde_json::json!({
            "kind": "array",
            "required": a.required,
            "annotations": a.annotations,
        }),
        FieldAst::Image(s) | FieldAst::File(s) => {
            let kind = if matches!(field, FieldAst::Image(_)) {
                "image"
            } else {
                "file"
            };
            serde_json::json!({
                "kind": kind,
                "required": s.required,
                "bucket": s.bucket,
                "annotations": s.annotations,
            })
        }
        FieldAst::Geo(g) => serde_json::json!({
            "kind": "geo",
            "required": g.required,
            "geoType": g.geo_type,
            "annotations": g.annotations,
        }),
        FieldAst::Vector(v) => serde_json::json!({
            "kind": "vector",
            "required": v.required,
            "dimensions": v.dimensions,
            "annotations": v.annotations,
        }),
        FieldAst::Blocks(b) => serde_json::json!({
            "kind": "blocks",
            "required": b.required,
            "blocks": b.blocks,
            "index": b.index,
            "annotations": b.annotations,
        }),
        FieldAst::Relation(r) => serde_json::json!({
            "kind": "relation",
            "cardinality": r.cardinality,
            "target": r.target,
            "annotations": r.annotations,
        }),
        FieldAst::Custom(c) => {
            let mut ann = c.annotations.clone();
            if ann.db.pg_type.is_empty() {
                ann.db.pg_type = c.pg_type.clone();
            }
            ann.db.unique = c.unique;
            ann.db.index = c.index;
            let mut v = serde_json::json!({
                "kind": "custom",
                "plugin": c.plugin,
                "fieldType": c.field_type,
                "tsType": c.ts_type,
                "required": c.required,
                "annotations": ann,
            });
            if let Some(ref d) = c.default {
                v["default"] = serde_json::to_value(d).unwrap_or(Value::Null);
            }
            if let Some(ref check) = c.check {
                v["check"] = Value::String(check.clone());
            }
            if c.read_only {
                v.as_object_mut().and_then(|o| {
                    o.get_mut("annotations")
                        .and_then(|a| a.as_object_mut())
                        .map(|ann_obj| {
                            ann_obj
                                .entry("platform")
                                .or_insert_with(|| Value::Object(serde_json::Map::new()));
                            if let Some(platform) =
                                ann_obj.get_mut("platform").and_then(|p| p.as_object_mut())
                            {
                                platform.insert("readOnly".into(), Value::Bool(true));
                            }
                        })
                });
            }
            v
        }
        FieldAst::Timestamps => serde_json::json!({ "kind": "timestamps" }),
        FieldAst::Publishable => serde_json::json!({ "kind": "publishable" }),
        FieldAst::SoftDelete => serde_json::json!({ "kind": "softDelete" }),
    }
}

fn scalar_to_v2(kind: &str, s: &ScalarFieldAst) -> Value {
    let mut v = serde_json::json!({
        "kind": kind,
        "required": s.required,
        "annotations": scalar_field_annotations(s),
    });
    if s.primary_key {
        v["primaryKey"] = Value::Bool(true);
    }
    if let Some(ref d) = s.default {
        v["default"] = serde_json::to_value(d).unwrap_or(Value::Null);
    }
    if !s.sources.is_empty() {
        v["sources"] = serde_json::to_value(&s.sources).unwrap_or(Value::Null);
    }
    if let Some(ref t) = s.template {
        v["template"] = Value::String(t.clone());
    }
    if s.localized {
        v["localized"] = Value::Bool(true);
    }
    v
}

fn scalar_field_annotations(s: &ScalarFieldAst) -> FieldAnnotations {
    if s.annotations.db.pg_type.is_empty() && !s.pg_type.is_empty() {
        let mut ann = s.annotations.clone();
        ann.db.pg_type = s.pg_type.clone();
        ann.db.unique = s.unique;
        ann.db.index = s.index;
        ann.platform.read_only = s.read_only;
        return ann;
    }
    s.annotations.clone()
}

fn slug_field_annotations(s: &SlugFieldAst) -> FieldAnnotations {
    let mut ann = s.annotations.clone();
    if ann.db.pg_type.is_empty() {
        ann.db.pg_type = s.pg_type.clone();
    }
    ann.db.unique = s.unique;
    ann.platform.read_only = s.read_only;
    ann
}

fn enum_field_annotations(e: &EnumFieldAst) -> FieldAnnotations {
    let mut ann = e.annotations.clone();
    if ann.db.pg_type.is_empty() {
        ann.db.pg_type = e.pg_type.clone();
    }
    ann.db.unique = e.unique;
    ann.platform.read_only = e.read_only;
    ann
}

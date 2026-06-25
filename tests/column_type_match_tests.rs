//! Column type matching — Postgres `information_schema` shapes vs schema AST fields.
//!
//! Guards against false drift (e.g. PostGIS `USER-DEFINED` + `udt_name=geography`).

use supatype_engine::{
    differ::{self, column_diff, Operation},
    introspector::tables::{DbColumn, DbTable},
    parser::{self, ast::FieldAst},
    state::database_state::DatabaseState,
};

fn pg_col(name: &str, data_type: &str, udt_name: &str, ordinal: i32, nullable: bool) -> DbColumn {
    DbColumn {
        name: name.into(),
        data_type: data_type.into(),
        udt_name: udt_name.into(),
        nullable,
        default: None,
        ordinal_position: ordinal,
    }
}

/// Typical `information_schema.columns` `(data_type, udt_name)` for a migrated column.
fn postgres_information_schema_types(field: &FieldAst) -> Option<(String, String)> {
    Some(match field {
        FieldAst::Text(_)
        | FieldAst::Email(_)
        | FieldAst::Url(_)
        | FieldAst::Slug(_)
        | FieldAst::Xml(_)
        | FieldAst::Color(_) => ("text".into(), "text".into()),
        FieldAst::Enum(e) if !e.pg_type.eq_ignore_ascii_case("ENUM") => {
            ("text".into(), "text".into())
        }
        FieldAst::Json(_)
        | FieldAst::RichText(_)
        | FieldAst::Image(_)
        | FieldAst::File(_)
        | FieldAst::Blocks(_) => ("jsonb".into(), "jsonb".into()),
        FieldAst::Bytes(_) => ("bytea".into(), "bytea".into()),
        FieldAst::Integer(_) | FieldAst::Serial(_) => ("integer".into(), "int4".into()),
        FieldAst::SmallInt(_) => ("smallint".into(), "int2".into()),
        FieldAst::BigInt(_) | FieldAst::BigSerial(_) => ("bigint".into(), "int8".into()),
        FieldAst::Float(_) => ("double precision".into(), "float8".into()),
        FieldAst::Boolean(_) => ("boolean".into(), "bool".into()),
        FieldAst::Uuid(_) => ("uuid".into(), "uuid".into()),
        FieldAst::Datetime(_) => ("timestamp with time zone".into(), "timestamptz".into()),
        FieldAst::Date(_) => ("date".into(), "date".into()),
        FieldAst::Timestamp(_) => ("timestamp without time zone".into(), "timestamp".into()),
        FieldAst::Ip(_) => ("inet".into(), "inet".into()),
        FieldAst::Cidr(_) => ("cidr".into(), "cidr".into()),
        FieldAst::Macaddr(_) => ("macaddr".into(), "macaddr".into()),
        FieldAst::Interval(_) => ("interval".into(), "interval".into()),
        FieldAst::TsQuery(_) => ("tsquery".into(), "tsquery".into()),
        FieldAst::TsVector(_) => ("tsvector".into(), "tsvector".into()),
        FieldAst::Money(_) => ("numeric".into(), "numeric".into()),
        FieldAst::Decimal(d) => {
            let data_type = match (d.precision, d.scale) {
                (Some(p), Some(s)) => format!("numeric({p},{s})"),
                (Some(p), None) => format!("numeric({p})"),
                _ => "numeric".into(),
            };
            (data_type, "numeric".into())
        }
        FieldAst::Array(a) => {
            let elem = a.element_type.to_lowercase();
            ("ARRAY".into(), format!("_{elem}"))
        }
        FieldAst::Geo(_) => ("USER-DEFINED".into(), "geography".into()),
        FieldAst::Vector(_) => ("USER-DEFINED".into(), "vector".into()),
        FieldAst::Enum(e) if e.pg_type.eq_ignore_ascii_case("ENUM") => {
            ("USER-DEFINED".into(), "post_status".into())
        }
        FieldAst::Relation(_)
        | FieldAst::Timestamps
        | FieldAst::Publishable
        | FieldAst::SoftDelete
        | FieldAst::Button(_)
        | FieldAst::Custom(_) => return None,
        other => panic!("add postgres_information_schema_types mapping for {other:?}"),
    })
}

fn is_type_drift_operation(op: &Operation) -> bool {
    match op {
        Operation::RecreateColumn { .. } => true,
        Operation::AlterColumn { changes, .. } => changes.get("type").is_some(),
        _ => false,
    }
}

fn collect_scalar_field_cases(fixtures: &[&str]) -> Vec<(String, FieldAst)> {
    let mut out = Vec::new();
    for fixture in fixtures {
        let ast = parser::parse(fixture).expect("fixture parses");
        for model in &ast.models {
            for (name, field) in &model.fields {
                if postgres_information_schema_types(field).is_some() {
                    out.push((name.clone(), field.clone()));
                }
            }
        }
    }
    out
}

#[test]
fn test_all_fixture_field_kinds_match_postgres_introspection() {
    let fixtures = [
        include_str!("fixtures/kitchen_sink.json"),
        include_str!("fixtures/geospatial.json"),
    ];
    let cases = collect_scalar_field_cases(&fixtures);

    assert!(
        cases.len() >= 20,
        "expected broad scalar coverage from kitchen_sink + geospatial, got {}",
        cases.len()
    );

    for (name, field) in &cases {
        let (data_type, udt_name) = postgres_information_schema_types(field).unwrap();
        let col = pg_col(name, &data_type, &udt_name, 1, true);
        assert!(
            column_diff::column_type_matches_introspected(field, &col),
            "field {name} should match information_schema data_type={data_type} udt_name={udt_name}"
        );
    }
}

#[test]
fn test_geo_user_defined_geography_matches_no_type_drift() {
    let fixture = include_str!("fixtures/geospatial.json");
    let ast = parser::parse(fixture).unwrap();
    let model = &ast.models[0];

    let mut columns: Vec<DbColumn> = model
        .fields
        .iter()
        .enumerate()
        .filter_map(|(i, (name, field))| {
            let (data_type, udt_name) = postgres_information_schema_types(field)?;
            Some(pg_col(name, &data_type, &udt_name, (i + 1) as i32, true))
        })
        .collect();

    columns.push(pg_col(
        "created_at",
        "timestamp with time zone",
        "timestamptz",
        columns.len() as i32 + 1,
        false,
    ));
    columns.push(pg_col(
        "updated_at",
        "timestamp with time zone",
        "timestamptz",
        columns.len() as i32 + 1,
        false,
    ));

    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: model.table_name().into(),
            columns,
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let type_drift: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| is_type_drift_operation(op))
        .collect();

    assert!(
        type_drift.is_empty(),
        "geospatial model should not drift on column types, got: {type_drift:?}; warnings: {:?}",
        diff.warnings
    );

    assert!(
        !diff
            .warnings
            .iter()
            .any(|w| w.contains("cannot cast geography")),
        "unexpected geo cast warning: {:?}",
        diff.warnings
    );
}

#[test]
fn test_geography_point_typmod_in_data_type_still_matches() {
    let fixture = include_str!("fixtures/geospatial.json");
    let ast = parser::parse(fixture).unwrap();
    let point = ast.models[0].fields.get("point").unwrap();

    let col = pg_col("point", "geography(Point,4326)", "geography", 1, false);
    assert!(column_diff::column_type_matches_introspected(point, &col));
}

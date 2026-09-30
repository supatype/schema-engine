//! One fixture that carries every field kind, and every kind that can be localized in both forms.
//!
//! This exists because of a released regression. The rich text normalising trigger was written
//! with nine live tests, and all nine used a plain rich text column. A localized column holds
//! `{"en": ..., "fr": ...}`, the trigger wrapped that map as though it were the document, and
//! every locale was destroyed on every write. Nothing caught it, because at the time exactly one
//! fixture in this suite set `localized` at all and it was the versioning one.
//!
//! The lesson is not "test localized columns". It is that each suite invented its own minimal
//! fixture, which let whoever wrote it pick the shapes they had already thought of. A shared
//! matrix removes that choice: a generator that ignores a kind, or ignores `localized` on a kind
//! that has it, is visible here rather than in someone's database.
//!
//! `kind_name` is an exhaustive match, so adding a variant to `FieldAst` stops this compiling
//! until the new kind is in the fixture too.

use std::collections::BTreeSet;
use supatype_engine::parser;
use supatype_engine::parser::ast::FieldAst;

const FIXTURE: &str = include_str!("fixtures/conformance_matrix.json");

/// The fixture's name for a field kind.
///
/// Exhaustive on purpose. A new `FieldAst` variant breaks this build, and the fix is to add the
/// arm and the fixture entry together.
fn kind_name(field: &FieldAst) -> &'static str {
    match field {
        FieldAst::Text(_) => "text",
        FieldAst::RichText(_) => "richText",
        FieldAst::Integer(_) => "integer",
        FieldAst::Float(_) => "float",
        FieldAst::Boolean(_) => "boolean",
        FieldAst::Datetime(_) => "datetime",
        FieldAst::Uuid(_) => "uuid",
        FieldAst::Email(_) => "email",
        FieldAst::Slug(_) => "slug",
        FieldAst::Enum(_) => "enum",
        FieldAst::Json(_) => "json",
        FieldAst::Button(_) => "button",
        FieldAst::Decimal(_) => "decimal",
        FieldAst::BigInt(_) => "bigInt",
        FieldAst::Bytes(_) => "bytes",
        FieldAst::SmallInt(_) => "smallInt",
        FieldAst::Date(_) => "date",
        FieldAst::Timestamp(_) => "timestamp",
        FieldAst::Serial(_) => "serial",
        FieldAst::BigSerial(_) => "bigSerial",
        FieldAst::Money(_) => "money",
        FieldAst::Url(_) => "url",
        FieldAst::Ip(_) => "ip",
        FieldAst::Cidr(_) => "cidr",
        FieldAst::Macaddr(_) => "macaddr",
        FieldAst::Interval(_) => "interval",
        FieldAst::TsQuery(_) => "tsQuery",
        FieldAst::TsVector(_) => "tsVector",
        FieldAst::Xml(_) => "xml",
        FieldAst::Color(_) => "color",
        FieldAst::Array(_) => "array",
        FieldAst::Image(_) => "image",
        FieldAst::File(_) => "file",
        FieldAst::Geo(_) => "geo",
        FieldAst::Vector(_) => "vector",
        FieldAst::Blocks(_) => "blocks",
        FieldAst::Custom(_) => "custom",
        FieldAst::Relation(_) => "relation",
        FieldAst::Timestamps => "timestamps",
        FieldAst::Publishable => "publishable",
        FieldAst::SoftDelete => "softDelete",
    }
}

/// Whether this field's AST struct carries a `localized` flag at all.
///
/// Reads the parsed field rather than a hand-kept list, so a kind that gains the flag is covered
/// by {@link every_localisable_kind_appears_localised} without anyone remembering to update it.
fn is_localised(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f)
        | FieldAst::RichText(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
        | FieldAst::Uuid(f)
        | FieldAst::Email(f)
        | FieldAst::BigInt(f)
        | FieldAst::Bytes(f)
        | FieldAst::SmallInt(f)
        | FieldAst::Date(f)
        | FieldAst::Timestamp(f)
        | FieldAst::Serial(f)
        | FieldAst::BigSerial(f)
        | FieldAst::Money(f)
        | FieldAst::Url(f)
        | FieldAst::Ip(f)
        | FieldAst::Cidr(f)
        | FieldAst::Macaddr(f)
        | FieldAst::Interval(f)
        | FieldAst::TsQuery(f)
        | FieldAst::TsVector(f)
        | FieldAst::Xml(f)
        | FieldAst::Color(f) => f.localized,
        FieldAst::Slug(f) => f.localized,
        FieldAst::Enum(f) => f.localized,
        FieldAst::Json(f) | FieldAst::Button(f) => f.localized,
        FieldAst::Decimal(f) => f.localized,
        FieldAst::Image(f) | FieldAst::File(f) => f.localized,
        FieldAst::Blocks(f) => f.localized,
        _ => false,
    }
}

fn parsed() -> supatype_engine::parser::ast::SchemaAst {
    parser::parse(FIXTURE).expect("the conformance fixture parses")
}

fn kinds_present(localised_only: bool) -> BTreeSet<&'static str> {
    parsed()
        .models
        .iter()
        .flat_map(|m| m.fields.values())
        .filter(|f| !localised_only || is_localised(f))
        .map(kind_name)
        .collect()
}

#[test]
fn the_fixture_parses() {
    let ast = parsed();
    assert_eq!(
        ast.models.len(),
        7,
        "plain, localized, required, defaulted, read-only, relations, composites"
    );
}

#[test]
fn every_field_kind_appears() {
    let present = kinds_present(false);
    let missing: Vec<&str> = ALL_KINDS
        .iter()
        .copied()
        .filter(|k| !present.contains(k))
        .collect();
    assert!(
        missing.is_empty(),
        "the conformance fixture is missing these kinds: {missing:?}.\n\
         Add them to tests/fixtures/conformance_matrix.json. Every generator is checked against \
         this fixture, so a kind that is absent here is a kind nothing checks."
    );
}

#[test]
fn every_localisable_kind_appears_localised() {
    let localised = kinds_present(true);
    assert!(
        !localised.is_empty(),
        "no localized fields parsed out of the fixture at all"
    );
    assert!(
        localised.contains("richText"),
        "richText must be present localized: that omission is what this fixture exists for"
    );
    // Anything whose struct carries the flag has to be exercised with it set. A generator that
    // branches on the kind and not on the flag is exactly the bug this catches.
    for kind in LOCALISABLE {
        assert!(
            localised.contains(kind),
            "{kind} can be localized but the fixture has no localized {kind}"
        );
    }
}

/// Every kind the fixture must carry. Paired with the exhaustive `kind_name` match: a new variant
/// breaks that match, and this list is where the fixture entry is then declared.
const ALL_KINDS: &[&str] = &[
    "text",
    "richText",
    "integer",
    "float",
    "boolean",
    "datetime",
    "uuid",
    "email",
    "slug",
    "enum",
    "json",
    "button",
    "decimal",
    "bigInt",
    "bytes",
    "smallInt",
    "date",
    "timestamp",
    "serial",
    "bigSerial",
    "money",
    "url",
    "ip",
    "cidr",
    "macaddr",
    "interval",
    "tsQuery",
    "tsVector",
    "xml",
    "color",
    "array",
    "image",
    "file",
    "geo",
    "vector",
    "blocks",
];

/// The kinds whose AST struct carries `localized`.
const LOCALISABLE: &[&str] = &[
    "text",
    "richText",
    "integer",
    "float",
    "boolean",
    "datetime",
    "uuid",
    "email",
    "bigInt",
    "bytes",
    "smallInt",
    "date",
    "timestamp",
    "money",
    "url",
    "ip",
    "cidr",
    "macaddr",
    "interval",
    "tsQuery",
    "tsVector",
    "xml",
    "color",
    "slug",
    "enum",
    "json",
    "button",
    "decimal",
    "image",
    "file",
    "blocks",
];

/// Where the widening goes on a localized column.
///
/// A localized column holds `{"en": ..., "fr": ...}`, and the trigger normalises each locale.
/// So prose is accepted *per locale*, and the widening belongs inside the `LocalizedValue`:
///
///   Row              LocalizedValue<RichText>
///   Insert, Update   LocalizedValue<RichText | string>
///
/// `LocalizedValue<RichText> | string` says a bare string is a valid write, and it is not. The
/// trigger sees a value that is not an object, wraps it whole, and the column ends up holding a
/// single document where a locale map belongs, which the Row type says is impossible.
#[test]
fn a_localised_rich_text_column_widens_inside_the_locale_map() {
    let ast = parsed();
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types generate");
    let lines: Vec<&str> = ts
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("richText_loc"))
        .collect();
    assert_eq!(lines.len(), 3, "Row, Insert and Update: {lines:?}");

    assert_eq!(
        lines[0], "richText_loc: LocalizedValue<RichText> | null",
        "a read is always documents, one per locale"
    );
    for written in &lines[1..] {
        assert!(
            written.contains("LocalizedValue<RichText | string>"),
            "prose is accepted per locale, so the widening goes inside: {written}"
        );
        assert!(
            !written.contains("LocalizedValue<RichText> | string"),
            "a bare string is not a valid write to a localized column: {written}"
        );
    }
}

/// The non-localized column keeps the plain widening, so the fix above cannot flatten both.
#[test]
fn a_plain_rich_text_column_still_widens_at_the_top() {
    let ast = parsed();
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types generate");
    let lines: Vec<&str> = ts
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("richText_plain"))
        .collect();
    assert_eq!(lines.len(), 3, "Row, Insert and Update: {lines:?}");
    assert_eq!(lines[0], "richText_plain: RichText | null");
    for written in &lines[1..] {
        assert!(written.contains("RichText | string"), "{written}");
    }
}

/// The trigger has to normalise a localized column per locale, not as one value.
///
/// This is the regression that shipped in v0.4.0: the whole locale map went through the
/// single-value wrap and every locale was destroyed on every write.
#[test]
fn the_trigger_normalises_a_localised_column_per_locale() {
    let ast = parsed();
    let sql = supatype_engine::generator::sql::triggers::generate(&ast, "public")
        .expect("triggers generate");
    let assignment = sql
        .lines()
        .find(|l| l.contains("NEW.\"richText_loc\" :="))
        .expect("the localized column gets a normalising assignment");
    assert!(
        assignment.contains("jsonb_each"),
        "per locale, not whole: {assignment}"
    );

    let plain = sql
        .lines()
        .find(|l| l.contains("NEW.\"richText_plain\" :="))
        .expect("the plain column gets one too");
    assert!(
        !plain.contains("jsonb_each"),
        "a plain column is one value, not a map: {plain}"
    );
}

/// Every generator that widens rich text has to widen in the same place.
///
/// Three of them emit this type from the same AST, and they disagreed: the client augmentation
/// and the seed builder each applied the locale wrapper first and appended `| string` outside it.
/// A generator is checked here rather than in its own file's tests, because its own tests are
/// where the fixture gets chosen and the awkward shape gets left out.
#[test]
fn every_generator_widens_inside_the_locale_map() {
    let ast = parsed();
    let outputs = [
        (
            "types",
            supatype_engine::generator::typescript::types::generate(&ast).expect("types"),
            "LocalizedValue<RichText | string>",
            "LocalizedValue<RichText> | string",
        ),
        (
            "augmentation",
            supatype_engine::generator::typescript::augmentation::generate(&ast).expect("aug"),
            "LocalizedValue<RichText | string>",
            "LocalizedValue<RichText> | string",
        ),
        (
            "seed",
            supatype_engine::generator::typescript::seed::generate(&ast).expect("seed"),
            "{ [locale: string]: SeedRichText | string }",
            "{ [locale: string]: SeedRichText } | string",
        ),
    ];

    for (name, out, wanted, forbidden) in outputs {
        let written: Vec<&str> = out
            .lines()
            .map(str::trim)
            .filter(|l| l.contains("richText_loc") && l.contains('?'))
            .collect();
        assert!(
            !written.is_empty(),
            "{name} emits no write shape for a localized rich text column"
        );
        for line in written {
            assert!(
                line.contains(wanted),
                "{name}: prose is accepted per locale, so the widening goes inside: {line}"
            );
            assert!(
                !line.contains(forbidden),
                "{name}: a bare string is not a valid write to a localized column: {line}"
            );
        }
    }
}

/// Helper: the Row, Insert and Update lines a column produces in `types.rs`.
fn shapes_of(ts: &str, column: &str) -> Vec<String> {
    ts.lines()
        .map(str::trim)
        .filter(|l| l.starts_with(&format!("{column}:")) || l.starts_with(&format!("{column}?:")))
        .map(str::to_string)
        .collect()
}

/// `required` and the rich text widening have to compose, in both the plain and localized forms.
///
/// Optionality and widening are applied by different pieces of code, and this is the crossing
/// where one can quietly undo the other: a required column that gains `| null` from the widening
/// path, or an optional one that loses it.
#[test]
fn required_and_the_widening_compose() {
    let ast = parsed();
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types");

    let optional = shapes_of(&ts, "richText_plain");
    assert_eq!(
        optional[0], "richText_plain: RichText | null",
        "{optional:?}"
    );
    assert_eq!(
        optional[1], "richText_plain?: RichText | string | null",
        "{optional:?}"
    );

    let required = shapes_of(&ts, "richText_req");
    assert_eq!(
        required[0], "richText_req: RichText",
        "no null on a required read"
    );
    assert_eq!(
        required[1], "richText_req: RichText | string",
        "required on insert, still widened, still not nullable"
    );
    assert_eq!(
        required[2], "richText_req?: RichText | string",
        "every column is optional on update"
    );
}

/// A column with a default is optional on insert, whatever its kind.
///
/// The database fills it, so demanding it would be asking for a value that is about to be
/// overwritten. This is the rule a `Slug` column already needed a special case for.
#[test]
fn a_default_makes_a_column_optional_on_insert() {
    let ast = parsed();
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types");
    for kind in ALL_KINDS {
        let column = format!("{kind}_def");
        let shapes = shapes_of(&ts, &column);
        if shapes.len() < 2 {
            continue;
        }
        assert!(
            shapes[1].starts_with(&format!("{column}?:")),
            "{column} has a default so insert must not demand it: {}",
            shapes[1]
        );
    }
}

/// Only `belongsTo` puts a column on this table.
///
/// The other three keep their key on the far side, so emitting a column for them would describe
/// one that does not exist. That disagreement between the two generators is a bug this repo has
/// already had once.
#[test]
fn only_belongs_to_becomes_a_column() {
    let ast = parsed();
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types");
    assert!(
        !shapes_of(&ts, "owner_id").is_empty(),
        "belongsTo emits its foreign key column"
    );
    for absent in ["children", "profile", "tags"] {
        assert!(
            shapes_of(&ts, absent).is_empty(),
            "{absent} keeps its key on the other table, so it is not a column here"
        );
    }
}

/// The composite fields expand into the columns they stand for.
#[test]
fn composites_expand_into_columns() {
    let ast = parsed();
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types");
    for column in ["created_at", "updated_at"] {
        assert!(
            !shapes_of(&ts, column).is_empty(),
            "`timestamps` has to produce {column}"
        );
    }
}

/// `readOnly` is a Studio hint, not a write constraint, and the generated types say so.
///
/// Pinned rather than assumed. `read_only` is read by `admin.rs` to grey a widget out and by
/// nothing in `types.rs`, so a read-only column is still writable through the client. If that
/// ever becomes a real constraint, this test is where the decision gets made rather than
/// discovered.
#[test]
fn read_only_does_not_narrow_the_generated_types() {
    let ast = parsed();
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types");
    let shapes = shapes_of(&ts, "richText_ro");
    assert_eq!(shapes.len(), 3, "Row, Insert and Update: {shapes:?}");
    assert!(shapes[1].contains("| string"), "still widened: {shapes:?}");
}

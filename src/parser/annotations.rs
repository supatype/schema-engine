use super::ast::{AccessAst, AccessRule, IndexAst};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelAnnotations {
    #[serde(default)]
    pub db: DbModelAnnotations,
    #[serde(default)]
    pub platform: PlatformModelAnnotations,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbModelAnnotations {
    #[serde(default)]
    pub table_name: String,
    #[serde(default)]
    pub indexes: Vec<IndexAst>,
    /// Model-level `CHECK` rules, in the same node vocabulary as access rules but with a narrower
    /// operand set. Beside `indexes` because both are things Postgres holds, unlike `access`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<AccessRule>,
    /// The names this model's table was called before, newest first, when the schema declares a
    /// rename (D1). Renames are declared, never guessed: the table differ renames the first of them
    /// the database still has to this table, and a declaration whose sources are all gone is a
    /// no-op, so it can stay. `renamedFrom` is one name or a list ([`RenamedFrom`]).
    #[serde(default, skip_serializing_if = "RenamedFrom::is_empty")]
    pub renamed_from: RenamedFrom,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformModelAnnotations {
    #[serde(default)]
    pub access: AccessAst,
    /// Columns Studio's list view searches, in the order the schema asked for.
    ///
    /// The CLI merges both spellings (`Searchable<T>` on a field and `searchable: [...]` on the
    /// model) into this one list, so there is nothing per-field to read here. Empty means the
    /// schema said nothing, not that search is off: see `derive_search_fields`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldAnnotations {
    #[serde(default)]
    pub db: DbFieldAnnotations,
    #[serde(default)]
    pub platform: PlatformFieldAnnotations,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbFieldAnnotations {
    #[serde(default)]
    pub pg_type: String,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub index: bool,
    #[serde(default)]
    pub foreign_key: Option<String>,
    #[serde(default)]
    pub server_generated: bool,
    /// Array element type (kind `array`).
    #[serde(default)]
    pub element_type: Option<String>,
    /// The names this field was called before, newest first, when the schema declares a rename
    /// (D1). The column differ renames the first old column the database still has to this
    /// field's, only when it is Supatype's and holds the declared type (or one that widens to it);
    /// a declaration whose sources are all gone is a no-op.
    #[serde(default, skip_serializing_if = "RenamedFrom::is_empty")]
    pub renamed_from: RenamedFrom,
    /// The field holds an `auth.users` id: the CLI marks a `SupatypeAuthUserId` field, since a UUID
    /// alone says nothing about what it identifies. A model keyed by one is a user's own, which an
    /// owner relation may point at (O1); an owner field without the mark is warned about (O2).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auth_user_id: bool,
    /// `SupatypeAuthUserId<{ onDelete }>`: the field opts in to a foreign key to `auth.users`, and
    /// this is what deleting the user does to the row. Absent, an auth user id has no key at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_user_on_delete: Option<AuthUserOnDelete>,
}

/// What deleting a user does to a row whose `SupatypeAuthUserId` field names them, spelled as the
/// schema spells it (`onDelete: "cascade"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthUserOnDelete {
    /// The row is deleted with its user.
    Cascade,
    /// The user cannot be deleted while they still own a row.
    Restrict,
    /// The row stays and the field becomes NULL, so only an optional field can take it.
    SetNull,
}

impl AuthUserOnDelete {
    /// The `ON DELETE` action of the key.
    pub fn sql(self) -> &'static str {
        match self {
            AuthUserOnDelete::Cascade => "CASCADE",
            AuthUserOnDelete::Restrict => "RESTRICT",
            AuthUserOnDelete::SetNull => "SET NULL",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformFieldAnnotations {
    #[serde(default)]
    pub editor: Option<String>,
    #[serde(default)]
    pub read_only: bool,
    /// The plugin composite this column came from, which Studio renders the composite's columns
    /// together under. Absent for a column the model declares itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<CompositeMembership>,
}

/// A column's place in a plugin composite (`WithPluginComposite<"seo", ...>`), as the CLI writes it
/// on every column the composite adds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompositeMembership {
    /// npm package of the plugin, e.g. `@supatype/plugin-seo`.
    pub plugin: String,
    /// The composite's name, e.g. `seo`.
    pub name: String,
    /// The composite's label, e.g. `SEO Meta`.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub collapsible: bool,
    #[serde(default)]
    pub default_collapsed: bool,
}

/// The old names a rename declares, newest first: `renamedFrom` as one name or a list. A list is
/// what lets a database two renames behind follow the chain back to the name it still has.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RenamedFrom(pub Vec<String>);

impl RenamedFrom {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

impl<'de> Deserialize<'de> for RenamedFrom {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        let names = match OneOrMany::deserialize(deserializer)? {
            OneOrMany::One(name) => vec![name],
            OneOrMany::Many(names) => names,
        };
        // An old name is looked up in the catalog, which holds it as Postgres kept it.
        Ok(RenamedFrom(
            names
                .iter()
                .map(|name| crate::managed::clip_identifier(name))
                .collect(),
        ))
    }
}

/// A dropped table or column and an added one, as a rename: `from` became `to`. What the engine
/// offers (`renameCandidates`) and what the project's rename journal records.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameCandidate {
    /// `table` or `column`.
    pub kind: String,
    /// The table, for a column; the old table's name, for a table.
    pub table: String,
    pub from: String,
    pub to: String,
}

/// One entry of the project's rename journal (`supatype/renames.json`, sent as the schema's
/// `renameJournal`): a rename and who declared it, when. The journal's own fields (`id`) are
/// ignored. Each entry is a declared rename, as `renamedFrom` is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredRename {
    #[serde(flatten)]
    pub rename: RenameCandidate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_at: Option<String>,
}

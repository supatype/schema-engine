//! Phase 1b of the managed-object ownership plan: the kinds the engine creates and never used to
//! read back. Triggers with their comments and bodies, functions, views, schemas, sequences, enum
//! types, grants, security labels, cron jobs and the RLS attributes of a table, all in
//! `CatalogState`, and all without an extension's objects mixed in.
//!
//! Read-only: nothing consumes any of this yet.

mod common;

use supatype_engine::{differ, generator::sql::migration, introspector, parser};

async fn exec(pool: &sqlx::PgPool, sql: &str) {
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .expect("fixture applies");
}

#[tokio::test]
async fn triggers_are_read_with_timing_events_function_and_comment() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.notes (id int PRIMARY KEY, body text, touched timestamptz);
             CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN NEW.touched := now(); RETURN NEW; END $$;
             CREATE TRIGGER notes_touch BEFORE INSERT OR UPDATE OF body ON public.notes
               FOR EACH ROW WHEN (NEW.body IS NOT NULL) EXECUTE FUNCTION public.touch();
             COMMENT ON TRIGGER notes_touch ON public.notes IS 'mine';",
        )
        .await;

        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();
        let t = catalog
            .triggers
            .iter()
            .find(|t| t.name == "notes_touch")
            .expect("trigger read");

        assert_eq!(t.schema, "public");
        assert_eq!(t.table, "notes");
        assert_eq!(t.timing, "BEFORE");
        assert_eq!(t.events, vec!["INSERT", "UPDATE"]);
        assert_eq!(t.columns, vec!["body"], "UPDATE OF columns");
        assert!(t.for_each_row);
        assert_eq!(t.function, "public.touch");
        assert!(
            t.definition.contains("WHEN ((new.body IS NOT NULL))"),
            "{}",
            t.definition
        );
        assert!(t.enabled);
        assert_eq!(t.comment.as_deref(), Some("mine"));
    })
    .await;
}

#[tokio::test]
async fn functions_carry_their_identity_body_and_properties() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE FUNCTION public.twice(n int) RETURNS int LANGUAGE sql IMMUTABLE
               AS $$ SELECT n * 2 $$;
             CREATE FUNCTION public.twice(n bigint) RETURNS bigint LANGUAGE sql IMMUTABLE
               AS $$ SELECT n * 2 $$;
             CREATE FUNCTION public.whoami() RETURNS text LANGUAGE sql SECURITY DEFINER
               AS $$ SELECT current_user::text $$;
             COMMENT ON FUNCTION public.whoami() IS 'definer';
             CREATE TABLE public.things (id int);
             CREATE FUNCTION public.describe(t public.things, at timestamptz, tags text[])
               RETURNS text LANGUAGE sql AS $$ SELECT '' $$;",
        )
        .await;

        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();
        let twice: Vec<_> = catalog
            .functions
            .iter()
            .filter(|f| f.name == "twice")
            .collect();
        assert_eq!(twice.len(), 2, "overloads are distinct functions");
        let args: Vec<&str> = twice
            .iter()
            .map(|f| f.identity_arguments.as_str())
            .collect();
        assert!(
            args.contains(&"n integer") && args.contains(&"n bigint"),
            "{args:?}"
        );
        let types: Vec<&str> = twice.iter().map(|f| f.identity_types.as_str()).collect();
        assert!(
            types.contains(&"integer") && types.contains(&"bigint"),
            "identity types carry no argument names: {types:?}"
        );
        // The row type is qualified even though `public` is on the search_path, the alias is
        // written out, and the array keeps its brackets: the same string `desired::identity`
        // builds from the declaration.
        let describe = catalog
            .functions
            .iter()
            .find(|f| f.name == "describe")
            .unwrap();
        assert_eq!(
            describe.identity_types,
            "public.things, timestamp with time zone, text[]"
        );
        assert_eq!(
            supatype_engine::desired::identity::function_key(
                "describe",
                "t public.things, at timestamptz, tags text[]"
            ),
            format!("describe({})", describe.identity_types)
        );
        assert!(twice
            .iter()
            .all(|f| f.volatility == "i" && f.language == "sql"));
        assert!(twice.iter().all(|f| f.body.contains("n * 2")));

        let whoami = catalog
            .functions
            .iter()
            .find(|f| f.name == "whoami")
            .unwrap();
        assert!(whoami.security_definer);
        assert_eq!(whoami.return_type, "text");
        assert_eq!(whoami.comment.as_deref(), Some("definer"));
    })
    .await;
}

#[tokio::test]
async fn views_schemas_sequences_and_enum_types_are_read_with_comments() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TYPE public.mood AS ENUM ('ok'); COMMENT ON TYPE public.mood IS 'feelings';
             CREATE TABLE public.items (id serial PRIMARY KEY, name text);
             CREATE SEQUENCE public.loose_seq; COMMENT ON SEQUENCE public.loose_seq IS 'free';
             CREATE VIEW public.item_names AS SELECT name FROM public.items;
             COMMENT ON VIEW public.item_names IS 'names only';
             CREATE MATERIALIZED VIEW public.item_count AS SELECT count(*) AS n FROM public.items;
             COMMENT ON SCHEMA public IS 'the project';",
        )
        .await;

        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();

        let v = catalog
            .views
            .iter()
            .find(|v| v.name == "item_names")
            .unwrap();
        assert!(!v.materialized);
        assert!(v.definition.contains("items"));
        assert_eq!(v.comment.as_deref(), Some("names only"));
        assert!(catalog
            .views
            .iter()
            .any(|v| v.name == "item_count" && v.materialized));

        let public = catalog.schemas.iter().find(|s| s.name == "public").unwrap();
        assert_eq!(public.comment.as_deref(), Some("the project"));
        assert!(
            !catalog.schemas.iter().any(|s| s.name == "draft"),
            "an engine schema that does not exist is not reported as existing"
        );

        let owned = catalog
            .sequences
            .iter()
            .find(|s| s.name == "items_id_seq")
            .unwrap();
        assert_eq!(owned.owned_by.as_deref(), Some("items.id"));
        let loose = catalog
            .sequences
            .iter()
            .find(|s| s.name == "loose_seq")
            .unwrap();
        assert!(loose.owned_by.is_none());
        assert_eq!(loose.comment.as_deref(), Some("free"));

        let mood = catalog
            .enum_types
            .iter()
            .find(|t| t.name == "mood")
            .unwrap();
        assert_eq!(mood.comment.as_deref(), Some("feelings"));
    })
    .await;
}

#[tokio::test]
async fn grants_are_aggregated_per_grantee_and_sorted() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.ledger (id int PRIMARY KEY, amount int, note text);
             DO $$ BEGIN CREATE ROLE reporting; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
             GRANT SELECT, INSERT ON public.ledger TO reporting;
             GRANT SELECT ON public.ledger TO PUBLIC;
             GRANT UPDATE (note) ON public.ledger TO reporting;",
        )
        .await;

        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();

        let reporting = catalog
            .table_grants
            .iter()
            .find(|g| g.table == "ledger" && g.grantee == "reporting")
            .expect("grant read");
        assert_eq!(reporting.privileges, vec!["INSERT", "SELECT"], "sorted");
        let public = catalog
            .table_grants
            .iter()
            .find(|g| g.table == "ledger" && g.grantee == "PUBLIC")
            .expect("PUBLIC is spelled as such");
        assert_eq!(public.privileges, vec!["SELECT"]);

        let note = catalog
            .column_grants
            .iter()
            .find(|g| g.table == "ledger" && g.column == "note" && g.grantee == "reporting")
            .expect("column grant read");
        assert_eq!(note.privileges, vec!["UPDATE"]);
    })
    .await;
}

#[tokio::test]
async fn rls_attributes_report_enabled_and_forced_separately() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.open (id int PRIMARY KEY);
             CREATE TABLE public.guarded (id int PRIMARY KEY);
             ALTER TABLE public.guarded ENABLE ROW LEVEL SECURITY;
             CREATE TABLE public.locked (id int PRIMARY KEY);
             ALTER TABLE public.locked ENABLE ROW LEVEL SECURITY;
             ALTER TABLE public.locked FORCE ROW LEVEL SECURITY;",
        )
        .await;

        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();
        let flags = |table: &str| {
            let a = catalog
                .rls_attributes
                .iter()
                .find(|a| a.table == table)
                .unwrap();
            (a.enabled, a.forced)
        };
        assert_eq!(flags("open"), (false, false));
        assert_eq!(flags("guarded"), (true, false));
        assert_eq!(flags("locked"), (true, true));
    })
    .await;
}

#[tokio::test]
async fn an_extensions_objects_are_not_reported() {
    common::with_integration_pool(|pool| async move {
        if sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS postgis")
            .execute(&pool)
            .await
            .is_err()
        {
            eprintln!("SKIP extension exclusion: this image has no postgis");
            return;
        }
        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();
        let postgis_fn = catalog
            .functions
            .iter()
            .find(|f| f.name.starts_with("st_") || f.name.starts_with("postgis_"));
        assert!(
            postgis_fn.is_none(),
            "an extension's function leaked in: {:?}",
            postgis_fn.map(|f| &f.name)
        );
        assert!(
            !catalog.views.iter().any(|v| v.name == "geometry_columns"),
            "an extension's view leaked in"
        );
        assert!(
            !catalog
                .rls_attributes
                .iter()
                .any(|a| a.table == "spatial_ref_sys"),
            "an extension's table leaked in"
        );
    })
    .await;
}

#[tokio::test]
async fn a_push_of_a_versioned_schema_is_visible_in_every_kind() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap();
        let empty = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &empty).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        exec(&pool, &sql).await;

        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();

        assert!(
            catalog
                .views
                .iter()
                .any(|v| v.schema == "draft" && v.name == "posts"),
            "the draft view the versions layer creates"
        );
        assert!(
            catalog
                .functions
                .iter()
                .any(|f| f.schema == "supatype" && f.name == "publish"),
            "the publish RPC the versions layer creates"
        );
        assert!(
            catalog
                .triggers
                .iter()
                .any(|t| t.name == "posts_versions_guard"),
            "the guard trigger on the versions table"
        );
        assert!(
            catalog.schemas.iter().any(|s| s.name == "_supatype")
                && catalog.schemas.iter().any(|s| s.name == "draft"),
            "the engine's own schemas"
        );
        assert!(
            catalog
                .rls_attributes
                .iter()
                .any(|a| a.table == "posts" && a.enabled),
            "RLS on the model table"
        );
        assert!(
            catalog
                .table_grants
                .iter()
                .any(|g| g.table == "posts" && g.grantee == "anon"),
            "the grants the push makes"
        );

        // The engine's own tables, with the constraints and indexes the push declared on them.
        let supatype = catalog
            .engine_tables
            .iter()
            .find(|e| e.schema == "_supatype")
            .expect("the _supatype schema has tables after a versioned push");
        for table in ["preview_links", "publishing_settings", "versioned_models"] {
            assert!(
                supatype.tables.iter().any(|t| t.name == table),
                "_supatype.{table} is read"
            );
        }
        assert!(
            supatype
                .constraints
                .iter()
                .any(|c| c.name == "preview_links_record_is_named"),
            "the check on preview_links is read with its explicit name"
        );
        assert!(
            supatype
                .indexes
                .iter()
                .any(|i| i.name == "preview_links_live_for_record"),
            "the partial index on preview_links is read"
        );
        // `auth` and `storage` are swept for functions and policies, never for tables.
        exec(
            &pool,
            "CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY)",
        )
        .await;
        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();
        assert!(
            !catalog
                .engine_tables
                .iter()
                .any(|e| e.schema == "auth" || e.schema == "storage"),
            "server-owned tables are not the engine's"
        );
    })
    .await;
}

//! Doctor and the check after a push know the objects the drafts layer makes (DR3).
//!
//! Every push of a schema with drafts ended in "Post-push drift (stale managed): Managed table
//! posts_versions is not in AST" and the same for the versions tables' `*_idx` indexes, though the
//! push had just made them, and `supatype doctor` said the same.

mod common;

use supatype_engine::differ::doctor::DoctorItem;
use supatype_engine::parser::{self, ast::SchemaAst};

fn versioned_ast() -> SchemaAst {
    parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap()
}

fn listed(items: &[DoctorItem]) -> Vec<String> {
    items
        .iter()
        .map(|i| format!("{} {}.{}: {}", i.kind, i.table, i.name, i.message))
        .collect()
}

#[tokio::test]
async fn a_push_with_drafts_leaves_nothing_stale() {
    common::with_integration_pool(|pool| async move {
        let ast = versioned_ast();
        common::push(&pool, &ast).await.expect("first push");
        let outcome = common::push(&pool, &ast).await.expect("second push");
        let drift: Vec<String> = format!("{outcome:?}")
            .split("Post-push drift")
            .skip(1)
            .map(|w| w.chars().take(160).collect())
            .collect();
        assert!(drift.is_empty(), "{drift:#?}");

        let report = common::doctor(&pool, &ast).await;
        assert!(
            report.stale_managed.is_empty(),
            "{:#?}",
            listed(&report.stale_managed)
        );
        assert!(!report.blocking, "{report:#?}");
    })
    .await;
}

/// The marketing site's content project as the CLI sends it: localized fields, a many-to-many
/// between a drafted model and one without drafts, and every model with drafts reading
/// `published_at <= now()`.
#[tokio::test]
async fn the_content_project_leaves_nothing_stale() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/drafts_content.json")).unwrap();
        common::push(&pool, &ast).await.expect("first push");
        let outcome = common::push(&pool, &ast).await.expect("second push");
        let drift: Vec<String> = format!("{outcome:?}")
            .split("Post-push drift")
            .skip(1)
            .map(|w| w.chars().take(160).collect())
            .collect();
        assert!(drift.is_empty(), "{drift:#?}");
        let report = common::doctor(&pool, &ast).await;
        assert!(
            report.stale_managed.is_empty(),
            "{:#?}",
            listed(&report.stale_managed)
        );
    })
    .await;
}

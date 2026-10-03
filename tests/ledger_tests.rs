//! Phase 3b of the managed-object ownership plan: the ledger table exists after bootstrap, and
//! rows round-trip through it by key.

mod common;

use supatype_engine::{
    desired::ObjectKey,
    introspector::fingerprint::ObjectKind,
    ledger::{self, LedgerRow, Status},
    state::migration_history,
};

fn row(kind: ObjectKind, parent: &str, name: &str, status: Status) -> LedgerRow {
    LedgerRow {
        key: ObjectKey {
            kind,
            schema: "public".into(),
            parent: parent.into(),
            name: name.into(),
        },
        desired_fp: ledger::desired_fingerprint(kind, "CREATE X;"),
        desired_sql: "CREATE X;".into(),
        live_fp: "0123456789abcdef".into(),
        live_def: "expression=CHECK (true)".into(),
        status,
        migration_id: None,
    }
}

#[tokio::test]
async fn bootstrap_creates_the_ledger_and_rows_round_trip_by_key() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();

        assert!(ledger::load(&mut conn).await.unwrap().is_empty());

        let check = row(ObjectKind::Check, "posts", "posts_title_check", Status::Managed);
        let index = row(ObjectKind::Index, "posts", "posts_slug_idx", Status::Adopted);
        ledger::upsert(&mut conn, &[index.clone(), check.clone()])
            .await
            .unwrap();
        assert_eq!(
            ledger::load(&mut conn).await.unwrap(),
            vec![check.clone(), index.clone()],
            "rows come back in key order"
        );

        // The same key again replaces the row rather than adding one.
        let mut edited = check.clone();
        edited.live_fp = "fedcba9876543210".into();
        edited.status = Status::Released;
        ledger::upsert(&mut conn, std::slice::from_ref(&edited))
            .await
            .unwrap();
        let rows = ledger::load(&mut conn).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], edited);

        ledger::delete(&mut conn, std::slice::from_ref(&index.key))
            .await
            .unwrap();
        assert_eq!(ledger::load(&mut conn).await.unwrap(), vec![edited.clone()]);

        // A migration row to point at, then the link.
        let migration_id: i32 = sqlx::query_scalar(
            "INSERT INTO _supatype.migrations (name, hash, engine_version)
             VALUES ('ledger_test', 'sha256:0', 'test') RETURNING id",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        ledger::set_migration(&mut conn, std::slice::from_ref(&edited.key), migration_id)
            .await
            .unwrap();
        assert_eq!(
            ledger::load(&mut conn).await.unwrap()[0].migration_id,
            Some(migration_id)
        );

        // A status outside the three the engine knows is refused by the table itself.
        let refused = sqlx::query(
            "INSERT INTO _supatype.managed_objects
                (kind, schema_name, parent, name, desired_fp, desired_sql, live_fp, live_def, status)
             VALUES ('check', 'public', 't', 'c', 'a', 'b', 'c', 'd', 'borrowed')",
        )
        .execute(&mut *conn)
        .await;
        assert!(refused.is_err(), "an unknown status must not be storable");
    })
    .await;
}

#[test]
fn kinds_and_statuses_round_trip_through_their_text_forms() {
    for kind in ObjectKind::ALL {
        assert_eq!(ObjectKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(
        ObjectKind::parse("rls_attributes"),
        Some(ObjectKind::RlsAttributes)
    );
    assert_eq!(ObjectKind::parse("rlsAttributes"), None);
    for status in [Status::Managed, Status::Adopted, Status::Released] {
        assert_eq!(Status::parse(status.as_str()), Some(status));
    }
}

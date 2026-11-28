use sqlx::PgPool;

#[tokio::test]
async fn migrations_create_identity_schema_and_tenant_policies() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for database integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("test database should accept connections");

    sqlx::migrate!("../../database/migrations")
        .run(&pool)
        .await
        .expect("all database migrations should apply");

    for table in [
        "tenants",
        "businesses",
        "business_locations",
        "users",
        "tenant_memberships",
        "roles",
        "permissions",
        "role_permissions",
        "membership_roles",
        "user_sessions",
        "audit_events",
        "auth_login_limits",
        "staff_invitations",
        "sumup_payment_attempts",
        "sumup_webhook_tokens",
        "pos_sales",
    ] {
        let exists: bool =
            sqlx::query_scalar("SELECT to_regclass(format('public.%I', $1)) IS NOT NULL")
                .bind(table)
                .fetch_one(&pool)
                .await
                .expect("table existence query should succeed");

        assert!(exists, "expected table {table} to exist");
    }

    let protected_tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = ANY($1) AND c.relrowsecurity",
    )
    .bind(vec![
        "businesses",
        "business_locations",
        "tenant_memberships",
        "audit_events",
        "staff_invitations",
        "sumup_payment_attempts",
        "pos_sales",
    ])
    .fetch_one(&pool)
    .await
    .expect("row-level security metadata query should succeed");

    assert_eq!(protected_tables, 7, "tenant-owned tables must enable RLS");

    pool.close().await;
}

#[tokio::test]
async fn row_level_security_hides_other_tenants_from_runtime_role() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for database integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("test database should accept connections");

    sqlx::migrate!("../../database/migrations")
        .run(&pool)
        .await
        .expect("all database migrations should apply");

    sqlx::query(
        "DO $$ BEGIN CREATE ROLE tomos_pos_rls_test NOLOGIN; \
         EXCEPTION WHEN duplicate_object THEN NULL; END $$",
    )
    .execute(&pool)
    .await
    .expect("test runtime role should exist");

    sqlx::query(
        "GRANT SELECT ON tenants, businesses, business_locations, tenant_memberships, audit_events, \
         pos_sales, sumup_payment_attempts TO tomos_pos_rls_test",
    )
    .execute(&pool)
    .await
    .expect("test runtime role should have read access");

    let tenant_a: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO tenants (slug, display_name) VALUES ($1, 'RLS Test A') RETURNING id",
    )
    .bind(format!("rls-a-{}", uuid::Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("first test tenant should be created");

    let tenant_b: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO tenants (slug, display_name) VALUES ($1, 'RLS Test B') RETURNING id",
    )
    .bind(format!("rls-b-{}", uuid::Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("second test tenant should be created");

    let suffix = uuid::Uuid::new_v4();
    let user_a: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, email_normalized, password_hash, display_name) \
         VALUES ($1, $2, 'test-hash', 'RLS User A') RETURNING id",
    )
    .bind(format!("rls-a-{suffix}@example.test"))
    .bind(format!("rls-a-{suffix}@example.test"))
    .fetch_one(&pool)
    .await
    .expect("first test user should be created");

    let user_b: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, email_normalized, password_hash, display_name) \
         VALUES ($1, $2, 'test-hash', 'RLS User B') RETURNING id",
    )
    .bind(format!("rls-b-{suffix}@example.test"))
    .bind(format!("rls-b-{suffix}@example.test"))
    .fetch_one(&pool)
    .await
    .expect("second test user should be created");

    for (tenant_id, user_id) in [(tenant_a, user_a), (tenant_b, user_b)] {
        sqlx::query("INSERT INTO tenant_memberships (tenant_id, user_id) VALUES ($1, $2)")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("test tenant membership should be created");
    }

    for (tenant_id, legal_name) in [(tenant_a, "Tenant A Ltd"), (tenant_b, "Tenant B Ltd")] {
        sqlx::query("INSERT INTO businesses (tenant_id, legal_name) VALUES ($1, $2)")
            .bind(tenant_id)
            .bind(legal_name)
            .execute(&pool)
            .await
            .expect("test business should be created");
    }

    let sale_a: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO pos_sales (tenant_id, amount_minor, currency, created_by) \
         VALUES ($1, 1250, 'GBP', $2) RETURNING id",
    )
    .bind(tenant_a)
    .bind(user_a)
    .fetch_one(&pool)
    .await
    .expect("tenant A sale should be created");
    let sale_b: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO pos_sales (tenant_id, amount_minor, currency, created_by) \
         VALUES ($1, 2500, 'GBP', $2) RETURNING id",
    )
    .bind(tenant_b)
    .bind(user_b)
    .fetch_one(&pool)
    .await
    .expect("tenant B sale should be created");

    for (tenant_id, sale_id, suffix) in [
        (tenant_a, sale_a, "a"),
        (tenant_b, sale_b, "b"),
    ] {
        sqlx::query(
            "INSERT INTO sumup_payment_attempts \
             (tenant_id, sale_id, reader_id, client_transaction_id, merchant_code, amount_minor, currency) \
             VALUES ($1, $2, 'reader-test', $3, 'merchant-test', 1250, 'GBP')",
        )
        .bind(tenant_id)
        .bind(sale_id)
        .bind(format!("rls-payment-{suffix}-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .expect("tenant payment attempt should be created");
    }

    let mut tx = pool
        .begin()
        .await
        .expect("RLS test transaction should start");
    sqlx::query("SET LOCAL ROLE tomos_pos_rls_test")
        .execute(&mut *tx)
        .await
        .expect("test should run as a non-owner application role");

    sqlx::query("SELECT set_config('app.user_id', $1, true)")
        .bind(user_a.to_string())
        .execute(&mut *tx)
        .await
        .expect("authenticated user context should be set");

    let own_memberships: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships")
        .fetch_one(&mut *tx)
        .await
        .expect("membership self-lookup should succeed");
    assert_eq!(
        own_memberships, 1,
        "user context must reveal only the authenticated user's memberships"
    );

    let sales_without_context: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pos_sales")
            .fetch_one(&mut *tx)
            .await
            .expect("sales query without tenant context should succeed");
    let attempts_without_context: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sumup_payment_attempts")
            .fetch_one(&mut *tx)
            .await
            .expect("payment attempts query without tenant context should succeed");
    assert_eq!(sales_without_context, 0, "no tenant context must hide sales");
    assert_eq!(attempts_without_context, 0, "no tenant context must hide payment attempts");

    let without_context: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM businesses")
        .fetch_one(&mut *tx)
        .await
        .expect("query without tenant context should succeed");
    assert_eq!(
        without_context, 0,
        "no tenant context must reveal no tenant rows"
    );

    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_a.to_string())
        .execute(&mut *tx)
        .await
        .expect("tenant context should be set transaction-locally");

    let visible_sales: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pos_sales")
        .fetch_one(&mut *tx)
        .await
        .expect("tenant-scoped sales query should succeed");
    let visible_attempts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sumup_payment_attempts")
            .fetch_one(&mut *tx)
            .await
            .expect("tenant-scoped payment attempt query should succeed");
    assert_eq!(visible_sales, 1, "tenant A must see only its own sale");
    assert_eq!(visible_attempts, 1, "tenant A must see only its own payment attempt");

    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM businesses")
        .fetch_one(&mut *tx)
        .await
        .expect("tenant-scoped query should succeed");
    assert_eq!(visible, 1, "tenant A must see only its own business");

    tx.rollback()
        .await
        .expect("RLS test transaction should roll back");
    pool.close().await;
}

#[tokio::test]
async fn audit_events_reject_update_delete_and_truncate() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for database integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("test database should accept connections");

    sqlx::migrate!("../../database/migrations")
        .run(&pool)
        .await
        .expect("all database migrations should apply");

    let tenant_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO tenants (slug, display_name) VALUES ($1, 'Audit append-only test') RETURNING id",
    )
    .bind(format!("audit-{}", uuid::Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("audit test tenant should be created");

    let mut tx = pool
        .begin()
        .await
        .expect("audit test transaction should start");
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("tenant context should be set");

    let event_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO audit_events (tenant_id, event_type, entity_type)
           VALUES ($1, 'test.created', 'test') RETURNING id"#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .expect("audit event should be insertable");

    sqlx::query("SAVEPOINT audit_update_attempt")
        .execute(&mut *tx)
        .await
        .expect("update savepoint should be created");
    let update = sqlx::query("UPDATE audit_events SET event_type = 'tampered' WHERE id = $1")
        .bind(event_id)
        .execute(&mut *tx)
        .await;
    assert!(update.is_err(), "audit event updates must be rejected");
    sqlx::query("ROLLBACK TO SAVEPOINT audit_update_attempt")
        .execute(&mut *tx)
        .await
        .expect("failed update should be rolled back to its savepoint");

    sqlx::query("SAVEPOINT audit_delete_attempt")
        .execute(&mut *tx)
        .await
        .expect("delete savepoint should be created");
    let delete = sqlx::query("DELETE FROM audit_events WHERE id = $1")
        .bind(event_id)
        .execute(&mut *tx)
        .await;
    assert!(delete.is_err(), "audit event deletion must be rejected");
    sqlx::query("ROLLBACK TO SAVEPOINT audit_delete_attempt")
        .execute(&mut *tx)
        .await
        .expect("failed delete should be rolled back to its savepoint");

    sqlx::query("SAVEPOINT audit_truncate_attempt")
        .execute(&mut *tx)
        .await
        .expect("truncate savepoint should be created");
    let truncate = sqlx::query("TRUNCATE audit_events").execute(&mut *tx).await;
    assert!(
        truncate.is_err(),
        "audit ledger truncation must be rejected"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT audit_truncate_attempt")
        .execute(&mut *tx)
        .await
        .expect("failed truncate should be rolled back to its savepoint");

    tx.rollback()
        .await
        .expect("audit test transaction should roll back");
    pool.close().await;
}

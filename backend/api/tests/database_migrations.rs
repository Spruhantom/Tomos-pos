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
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT to_regclass(format('public.%I', $1)) IS NOT NULL",
        )
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
    ])
    .fetch_one(&pool)
    .await
    .expect("row-level security metadata query should succeed");

    assert_eq!(protected_tables, 4, "tenant-owned tables must enable RLS");

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
        "GRANT SELECT ON tenants, businesses, business_locations, tenant_memberships, audit_events \
         TO tomos_pos_rls_test",
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

    for (tenant_id, legal_name) in [(tenant_a, "Tenant A Ltd"), (tenant_b, "Tenant B Ltd")] {
        sqlx::query("INSERT INTO businesses (tenant_id, legal_name) VALUES ($1, $2)")
            .bind(tenant_id)
            .bind(legal_name)
            .execute(&pool)
            .await
            .expect("test business should be created");
    }

    let mut tx = pool.begin().await.expect("RLS test transaction should start");
    sqlx::query("SET LOCAL ROLE tomos_pos_rls_test")
        .execute(&mut *tx)
        .await
        .expect("test should run as a non-owner application role");

    let without_context: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM businesses")
        .fetch_one(&mut *tx)
        .await
        .expect("query without tenant context should succeed");
    assert_eq!(without_context, 0, "no tenant context must reveal no tenant rows");

    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_a.to_string())
        .execute(&mut *tx)
        .await
        .expect("tenant context should be set transaction-locally");

    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM businesses")
        .fetch_one(&mut *tx)
        .await
        .expect("tenant-scoped query should succeed");
    assert_eq!(visible, 1, "tenant A must see only its own business");

    tx.rollback().await.expect("RLS test transaction should roll back");
    pool.close().await;
}

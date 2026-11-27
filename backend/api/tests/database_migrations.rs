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

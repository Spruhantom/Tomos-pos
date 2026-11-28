use sqlx::PgPool;

async fn acquire_database_test_lock(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut connection = pool
        .acquire()
        .await
        .expect("database test lock connection should be acquired");
    sqlx::query("SELECT pg_advisory_lock(731942, 1)")
        .execute(&mut *connection)
        .await
        .expect("database integration tests should be serialized");
    connection
}

async fn release_database_test_lock(mut connection: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    sqlx::query("SELECT pg_advisory_unlock(731942, 1)")
        .execute(&mut *connection)
        .await
        .expect("database integration test lock should be released");
}

#[tokio::test]
async fn migrations_create_identity_schema_and_tenant_policies() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for database integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("test database should accept connections");
    let test_lock = acquire_database_test_lock(&pool).await;

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
    ])
    .fetch_one(&pool)
    .await
    .expect("row-level security metadata query should succeed");

    assert_eq!(protected_tables, 5, "tenant-owned tables must enable RLS");

    release_database_test_lock(test_lock).await;
    pool.close().await;
}

#[tokio::test]
async fn row_level_security_hides_other_tenants_from_runtime_role() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for database integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("test database should accept connections");
    let test_lock = acquire_database_test_lock(&pool).await;

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
        "GRANT SELECT ON tenants, businesses, business_locations, tenant_memberships, audit_events, staff_invitations \
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
        let business_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO businesses (tenant_id, legal_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(tenant_id)
        .bind(legal_name)
        .fetch_one(&pool)
        .await
        .expect("test business should be created");
        sqlx::query(
            "INSERT INTO business_locations (tenant_id, business_id, name, location_code) \
             VALUES ($1, $2, $3, 'MAIN')",
        )
        .bind(tenant_id)
        .bind(business_id)
        .bind(format!("{legal_name} Main"))
        .execute(&pool)
        .await
        .expect("test business location should be created");
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

    let visible_tenants: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM tenant_memberships ORDER BY tenant_id")
            .fetch_all(&mut *tx)
            .await
            .expect("authenticated tenant discovery query should succeed");
    assert_eq!(
        visible_tenants,
        vec![tenant_a],
        "tenant discovery must return only the authenticated user's own tenant"
    );

    let without_context: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM businesses")
        .fetch_one(&mut *tx)
        .await
        .expect("query without tenant context should succeed");
    assert_eq!(
        without_context, 0,
        "no tenant context must reveal no tenant rows"
    );
    let locations_without_context: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM business_locations")
            .fetch_one(&mut *tx)
            .await
            .expect("location query without tenant context should succeed");
    assert_eq!(
        locations_without_context, 0,
        "no tenant context must reveal no business locations"
    );

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

    let own_locations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM business_locations")
        .fetch_one(&mut *tx)
        .await
        .expect("tenant-scoped location query should succeed");
    assert_eq!(own_locations, 1, "tenant A must see only its own location");

    let other_tenant_locations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM business_locations WHERE name = 'Tenant B Ltd Main'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("cross-tenant location lookup should succeed");
    assert_eq!(
        other_tenant_locations, 0,
        "tenant A must not see tenant B's location"
    );

    tx.rollback()
        .await
        .expect("RLS test transaction should roll back");
    release_database_test_lock(test_lock).await;
    pool.close().await;
}

#[tokio::test]
async fn audit_events_reject_update_delete_and_truncate() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for database integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("test database should accept connections");
    let test_lock = acquire_database_test_lock(&pool).await;

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
    release_database_test_lock(test_lock).await;
    pool.close().await;
}

#[tokio::test]
async fn staff_invitation_rls_scopes_tenant_and_token_lookups() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for database integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("database should accept connections");
    let test_lock = acquire_database_test_lock(&pool).await;

    sqlx::migrate!("../../database/migrations")
        .run(&pool)
        .await
        .expect("all database migrations should apply");

    sqlx::query(
        "DO $$ BEGIN CREATE ROLE tomos_pos_invitation_rls_test NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$",
    )
    .execute(&pool)
    .await
    .expect("invitation runtime role should exist");
    sqlx::query("GRANT SELECT ON staff_invitations TO tomos_pos_invitation_rls_test")
        .execute(&pool)
        .await
        .expect("invitation runtime role should have read access");

    let tenant_a: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO tenants (slug, display_name) VALUES ($1, 'Invitation RLS A') RETURNING id",
    )
    .bind(format!("invite-a-{}", uuid::Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("tenant A should be created");
    let tenant_b: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO tenants (slug, display_name) VALUES ($1, 'Invitation RLS B') RETURNING id",
    )
    .bind(format!("invite-b-{}", uuid::Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("tenant B should be created");

    for (tenant_id, suffix, token_hash) in [
        (tenant_a, "a", "invitation-token-hash-a"),
        (tenant_b, "b", "invitation-token-hash-b"),
    ] {
        let inviter_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO users (email, email_normalized, password_hash, display_name) VALUES ($1, $1, 'test-hash', 'Invitation inviter') RETURNING id",
        )
        .bind(format!("inviter-{suffix}-{}@example.test", uuid::Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .expect("inviter account should be created");
        let role_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO roles (tenant_id, role_key, display_name, is_system) VALUES ($1, 'staff-test', 'Staff test', FALSE) RETURNING id",
        )
        .bind(tenant_id)
        .fetch_one(&pool)
        .await
        .expect("tenant staff role should be created");
        sqlx::query(
            "INSERT INTO staff_invitations (tenant_id, email_normalized, role_id, invited_by, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5, now() + interval '7 days')",
        )
        .bind(tenant_id)
        .bind(format!("new-{suffix}-{}@example.test", uuid::Uuid::new_v4()))
        .bind(role_id)
        .bind(inviter_id)
        .bind(token_hash)
        .execute(&pool)
        .await
        .expect("invitation should be created");
    }

    let mut tx = pool.begin().await.expect("RLS transaction should start");
    sqlx::query("SET LOCAL ROLE tomos_pos_invitation_rls_test")
        .execute(&mut *tx)
        .await
        .expect("queries should run as the non-owner runtime role");

    let no_context: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM staff_invitations")
        .fetch_one(&mut *tx)
        .await
        .expect("query without context should succeed");
    assert_eq!(no_context, 0, "no context must reveal no invitations");

    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_a.to_string())
        .execute(&mut *tx)
        .await
        .expect("tenant A context should be set");
    let tenant_a_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM staff_invitations")
        .fetch_one(&mut *tx)
        .await
        .expect("tenant A invitation query should succeed");
    assert_eq!(tenant_a_count, 1, "tenant A must see only its invitation");

    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_b.to_string())
        .execute(&mut *tx)
        .await
        .expect("tenant B context should be set");
    let tenant_b_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM staff_invitations")
        .fetch_one(&mut *tx)
        .await
        .expect("tenant B invitation query should succeed");
    assert_eq!(tenant_b_count, 1, "tenant B must see only its invitation");

    sqlx::query("SELECT set_config('app.tenant_id', '', true)")
        .execute(&mut *tx)
        .await
        .expect("tenant context should be cleared");
    sqlx::query("SELECT set_config('app.invitation_token_hash', $1, true)")
        .bind("invitation-token-hash-a")
        .execute(&mut *tx)
        .await
        .expect("invitation token context should be set");
    let token_matches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM staff_invitations WHERE token_hash = 'invitation-token-hash-a'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("token-scoped invitation lookup should succeed");
    assert_eq!(
        token_matches, 1,
        "the presented token digest must reveal only its matching invitation"
    );

    tx.rollback()
        .await
        .expect("RLS transaction should roll back");
    release_database_test_lock(test_lock).await;
    pool.close().await;
}

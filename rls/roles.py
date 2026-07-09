"""The SQL that provisions a restricted application login role for a forced-RLS schema.

The moat `FORCE ROW LEVEL SECURITY` depends on is a login role that is NOSUPERUSER NOBYPASSRLS: a
superuser or a `BYPASSRLS` role reads every row regardless of policy, so the application has to
connect as a role that cannot, while every table it touches is owned by a different (migration) role
so `FORCE` has teeth. This builds that role's `CREATE ROLE` plus the schema-usage and
default-privilege grants that hand it plain CRUD, parameterized by name and password. A bootstrap
that runs before any Python (a Postgres `docker-entrypoint-initdb.d` script, say) has to inline
these itself, so this is the shared source of the exact statement shape rather than the wiring.
"""


def app_role_statements(role: str, password: str) -> list[str]:
    """The `CREATE ROLE` and default-privilege grants provisioning a restricted app login role.

    Every statement is plain DDL a caller executes in order against a fresh database as the owning
    (migration) role, so the default privileges below apply to every table and sequence that role
    later creates. No `IF NOT EXISTS` guard on the role, matching a one-shot bootstrap against a
    fresh cluster; a caller that may rerun wraps the create in its own existence check.

    role: the login role to create, e.g. `aizk_app`.
    password: the role's login password, inlined into the `CREATE ROLE`.
    """
    return [
        f"CREATE ROLE {role} LOGIN PASSWORD '{password}' "
        "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE",
        f"GRANT USAGE ON SCHEMA public TO {role}",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role}",
    ]

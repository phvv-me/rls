from enum import StrEnum


class RLSAction(StrEnum):
    """PostgreSQL row security DDL templates."""

    enable = "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"
    disable = "ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"
    force = "ALTER TABLE {table} FORCE ROW LEVEL SECURITY"
    no_force = "ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"
    create = "CREATE POLICY {name} ON {table} AS {mode} FOR {command} TO {roles}{using}{check}"
    drop = "DROP POLICY IF EXISTS {name} ON {table}"

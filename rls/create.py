"""Apply every declared policy directly against a connection, no Alembic involved.

Ported from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls)'s `create_policies.py`, for
an application that calls `metadata.create_all()` and wants row level security applied in the same
breath rather than through a migration. Upstream's version enabled row security but never forced
it on this path either (`ALTER TABLE ... FORCE ROW LEVEL SECURITY` was only ever emitted here, not
on the Alembic path); this port emits the same `enable_statements` the Alembic ops layer does, so
both paths force row security identically rather than the direct path being the only one that does.
"""

import sqlalchemy as sa
from sqlalchemy.engine import Connection
from sqlalchemy.sql.schema import MetaData

from .policy import compile_policy
from .policy import enable_statements


def create_policies(metadata: MetaData, connection: Connection) -> None:
    """Create every table's declared policies directly against `connection`, then commit.

    metadata: the registry `register()` was called on, carrying `metadata.info["rls_policies"]`
        and, when set, `metadata.info["rls_grant_role"]`.
    connection: an open connection; the caller owns opening it, this function commits it.
    """
    grant_role = metadata.info.get("rls_grant_role")
    for table, policies in metadata.info.get("rls_policies", {}).items():
        if not policies:
            continue
        compiled = [compile_policy(policy) for policy in policies]
        for statement in enable_statements(table, compiled, grant_role):
            connection.execute(sa.text(statement))
    connection.commit()

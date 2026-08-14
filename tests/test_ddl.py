import sqlalchemy as sa
from conftest import CockroachDialect
from conftest import compile_ddl
from conftest import rls_states
from hypothesis import given
from sqlalchemy.dialects.postgresql import CreatePolicy
from sqlalchemy.dialects.postgresql import Policy

import rls


def test_fork_policy_ddl_quotes_identifiers() -> None:
    """RLSAlchemy feeds declarations into SQLAlchemy's safely quoted policy DDL."""
    table = sa.Table("items; DROP TABLE users", sa.MetaData(), schema="private data")
    statement = CreatePolicy(
        Policy(
            'read"; RESET ROLE; --',
            table,
            command="SELECT",
            using="true",
            roles="account reader",
            permissive=False,
        )
    )
    sql = compile_ddl(statement)
    assert '"private data"."items; DROP TABLE users"' in sql
    assert '"read""; RESET ROLE; --"' in sql
    assert 'TO "account reader"' in sql
    assert "AS RESTRICTIVE" in sql


def test_cockroachdb_inherits_the_fork_policy_ddl() -> None:
    """The CockroachDB dialect inherits SQLAlchemy's PostgreSQL policy compiler."""
    table = sa.Table("order", sa.MetaData(), sa.Column("id", sa.Integer()))
    statement = CreatePolicy(
        Policy(
            "rls_select",
            table,
            command="SELECT",
            using="id > 0",
        )
    )

    assert str(statement.compile(dialect=CockroachDialect())).startswith(
        'CREATE POLICY rls_select ON "order"'
    )


@given(state=rls_states())
def test_apply_and_drop_are_ordered_inverse_sequences(state: rls.RLSState) -> None:
    """Apply toggles flags then creates each policy; drop reverses policies then flags."""
    table = sa.Table("items", sa.MetaData())
    applied = [compile_ddl(statement) for statement in rls.apply_statements(table, state)]
    dropped = [compile_ddl(statement) for statement in rls.drop_statements(table, state)]
    count = len(state.policies)
    assert len(applied) == len(dropped) == 2 + count
    enable = "ENABLE" if state.enabled else "DISABLE"
    force = "FORCE" if state.forced else "NO FORCE"
    assert applied[0] == f"ALTER TABLE items {enable} ROW LEVEL SECURITY"
    assert applied[1] == f"ALTER TABLE items {force} ROW LEVEL SECURITY"
    assert dropped[-2:] == [
        "ALTER TABLE items NO FORCE ROW LEVEL SECURITY",
        "ALTER TABLE items DISABLE ROW LEVEL SECURITY",
    ]
    created = [line.split()[2] for line in applied[2:]]
    removed = [line.split()[4] for line in dropped[:count]]
    assert removed == list(reversed(created))

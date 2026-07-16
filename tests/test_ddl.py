import pytest
import sqlalchemy as sa
from conftest import compile_ddl
from conftest import rls_states
from hypothesis import given

import rls
from rls.ddl import RLSAction
from rls.ddl import RLSStatement


def test_identifiers_are_dialect_quoted_and_construction_is_guarded() -> None:
    """Hostile names are quoted as data, and the two invalid constructions fail fast."""
    table = sa.Table("items; DROP TABLE users", sa.MetaData(), schema="private data")
    policy = rls.CompiledPolicy(
        name='read"; RESET ROLE; --',
        command=rls.Command.select,
        using="true",
        roles=("account reader",),
        permissive=False,
    )
    sql = compile_ddl(RLSStatement(table, RLSAction.create, policy=policy))
    assert '"private data"."items; DROP TABLE users"' in sql
    assert '"read""; RESET ROLE; --"' in sql
    assert 'TO "account reader"' in sql
    assert "AS RESTRICTIVE" in sql
    with pytest.raises(ValueError, match="create requires"):
        RLSStatement(table, RLSAction.create)
    with pytest.raises(ValueError, match="drop requires"):
        RLSStatement(table, RLSAction.drop)


@given(state=rls_states())
def test_apply_and_drop_are_ordered_inverse_sequences(state: rls.RLSState) -> None:
    """Apply toggles flags then creates each policy; drop reverses the policies then the flags."""
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

import datetime
import uuid

import pytest
import sqlalchemy as sa
from conftest import RecordingConnection
from conftest import Standing
from conftest import TenantGate
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

import rls
from rls.context import serialize
from rls.context import sql_type
from rls.context.serialize import quote_array_item
from rls.context.types import ContextAnnotation

_SCALAR_SQL: dict[type, type[sa.types.TypeEngine]] = {
    uuid.UUID: sa.Uuid,
    bool: sa.Boolean,
    int: sa.BigInteger,
    float: sa.Double,
    str: sa.Text,
    datetime.datetime: sa.DateTime,
    datetime.date: sa.Date,
}


@given(scalar=st.sampled_from(list(_SCALAR_SQL)))
def test_sql_type_covers_scalar_optional_and_array(scalar: type) -> None:
    """Every supported scalar maps, optionals unwrap, and homogeneous tuples become arrays."""
    expected = _SCALAR_SQL[scalar]
    assert isinstance(sql_type(scalar), expected)
    assert isinstance(sql_type(scalar | None), expected)
    array = sql_type(tuple[scalar, ...])
    assert isinstance(array, postgresql.ARRAY)
    assert isinstance(array.item_type, expected)


@pytest.mark.parametrize(
    ("annotation", "match"),
    [
        (tuple[str, int], "homogeneous"),
        (str | int, "one optional"),
        (dict, "no PostgreSQL cast"),
        (list[str], "no PostgreSQL cast"),
    ],
)
def test_sql_type_rejects_annotations_outside_the_grammar(
    annotation: ContextAnnotation, match: str
) -> None:
    """Heterogeneous tuples, multi-arm unions, and unknown types are rejected."""
    with pytest.raises(TypeError, match=match):
        sql_type(annotation)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, ""),
        (True, "true"),
        (False, "false"),
        (datetime.date(2026, 7, 10), "2026-07-10"),
        (datetime.datetime(2026, 7, 10, 12, 0), "2026-07-10T12:00:00"),
        (7, "7"),
        (3.5, "3.5"),
        (uuid.UUID(int=1), "00000000-0000-0000-0000-000000000001"),
        (('quo"te', "back\\slash"), '{"quo\\"te","back\\\\slash"}'),
    ],
)
def test_serialize_renders_scalars_and_escaped_arrays(
    value: rls.ContextValue, expected: str
) -> None:
    """Scalars and tuples serialize to the exact, escaped PostgreSQL setting text."""
    assert serialize(value) == expected


def _unquote_array_item(quoted: str) -> str:
    inner = quoted[1:-1]
    out: list[str] = []
    escaped = False
    for char in inner:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    return "".join(out)


@given(text=st.text())
def test_array_item_quoting_is_a_reversible_escape(text: str) -> None:
    """Any string, quotes and backslashes included, survives array quoting unchanged."""
    assert _unquote_array_item(quote_array_item(text)) == text


def test_setting_builds_typed_reads_from_a_validated_namespace() -> None:
    """The namespace derives or is set, invalid ones raise, and access casts a scalar subquery."""
    assert Standing.__namespace__ == "app"
    assert TenantGate.__namespace__ == "tenant_gate"
    with pytest.raises(ValueError, match="namespace"):

        class Bad(rls.Context, prefix="bad prefix"):
            pass

    orgs = str(
        Standing.setting("orgs").compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert "current_setting('app.orgs', true)" in orgs
    assert "AS UUID[]" in orgs
    assert orgs.lstrip().startswith("(SELECT")
    tenant = str(
        TenantGate.setting("tenant").compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert "current_setting('tenant_gate.tenant', true)" in tenant
    direct = str(
        rls.current_setting("uid", sa.Uuid(), prefix="app").compile(dialect=postgresql.dialect())
    )
    assert "current_setting" in direct and "CAST" in direct and "SELECT" in direct
    with pytest.raises(ValueError, match="identifiers"):
        rls.current_setting("bad name", sa.Uuid(), prefix="app")


def test_after_begin_binds_every_field_once_and_skips_empty_sessions() -> None:
    """A context session issues one cached `set_config` per field; a plain session issues none."""
    user, other = uuid.UUID(int=1), uuid.UUID(int=2)
    standing = Standing(
        uid=user,
        orgs=(user, other),
        active=True,
        expires=datetime.date(2026, 7, 10),
        lens=None,
    )
    assert standing.settings is standing.settings
    session = Session(info=standing.info())
    assert rls.has_context(session)
    connection = RecordingConnection()
    rls.context.bind_context(session, session.get_transaction(), connection)
    statement, parameters = connection.calls[0]
    assert str(statement).count("set_config(") == 5
    assert parameters == {
        "rls_value_0": str(user),
        "rls_value_1": f'{{"{user}","{other}"}}',
        "rls_value_2": "true",
        "rls_value_3": "2026-07-10",
        "rls_value_4": "",
    }
    plain = RecordingConnection()
    empty = Session()
    rls.context.bind_context(empty, empty.get_transaction(), plain)
    assert plain.calls == []
    assert not rls.has_context(empty)

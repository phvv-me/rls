import re

import sqlalchemy as sa
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.type_api import TypeEngine

from ..exceptions import ContextError

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_valid_setting_name(name: str) -> bool:
    """Whether a name is safe as a PostgreSQL custom setting identifier."""
    return _NAME.fullmatch(name) is not None


def is_valid_qualified_setting_name(name: str) -> bool:
    """Whether a dotted custom setting name has safe identifier components."""
    parts = name.split(".")
    return len(parts) >= 2 and all(is_valid_setting_name(part) for part in parts)


def current_setting[T](name: str, type_: TypeEngine[T], prefix: str) -> ColumnElement[T]:
    """Read and cast one portable transaction-local PostgreSQL setting."""
    qualified = f"{prefix}.{name}"
    if not is_valid_qualified_setting_name(qualified):
        raise ContextError("PostgreSQL setting names must be identifiers")
    read = sa.func.nullif(sa.func.current_setting(qualified, True), "")
    return read.cast(type_)

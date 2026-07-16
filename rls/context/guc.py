import re

import sqlalchemy as sa
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.type_api import TypeEngine

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def valid_setting_name(name: str) -> bool:
    """Whether a name is safe as a PostgreSQL custom setting identifier."""
    return _NAME.fullmatch(name) is not None


def current_setting[T](name: str, type_: TypeEngine[T], prefix: str) -> ColumnElement[T]:
    """Read and cast one transaction-local PostgreSQL setting.

    The scalar-subquery wrapper is deliberate. PostgreSQL hoists it into an InitPlan
    evaluated once per statement, so a policy pays one setting read instead of one per row.
    """
    if not valid_setting_name(name) or not valid_setting_name(prefix):
        raise ValueError("PostgreSQL setting names must be identifiers")
    read = sa.func.nullif(sa.func.current_setting(f"{prefix}.{name}", True), "")
    return sa.select(read.cast(type_).label(name)).scalar_subquery()

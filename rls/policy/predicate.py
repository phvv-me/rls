from typing import Callable
from typing import cast

from sqlalchemy.dialects import postgresql
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.sql.elements import ColumnElement

type Predicate = ColumnElement[bool]

_POSTGRESQL = cast(Callable[[], Dialect], postgresql.dialect)()


def compile_expression(expression: Predicate) -> str:
    """Compile a predicate with PostgreSQL literals inlined."""
    return str(expression.compile(dialect=_POSTGRESQL, compile_kwargs={"literal_binds": True}))

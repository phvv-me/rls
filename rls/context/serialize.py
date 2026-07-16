import datetime
import uuid

from pydantic import BaseModel
from pydantic_core import to_json

type ContextScalar = str | int | float | bool | uuid.UUID | datetime.date | datetime.datetime
type ContextValue = (
    ContextScalar
    | tuple[ContextScalar, ...]
    | frozenset[ContextScalar]
    | dict[str, ContextValue]
    | BaseModel
    | None
)


def serialize(value: ContextValue) -> str:
    """Serialize a context value to PostgreSQL setting text."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if isinstance(value, (str, int, float, uuid.UUID)):
        return str(value)
    if isinstance(value, (dict, BaseModel)):
        return to_json(value).decode()
    return "{" + ",".join(quote_array_item(item) for item in value) + "}"


def quote_array_item(value: ContextScalar) -> str:
    """Quote one PostgreSQL array item."""
    rendered = serialize(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{rendered}"'

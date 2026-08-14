import datetime
import types
import typing
import uuid
from typing import cast

import sqlalchemy as sa
from pydantic import BaseModel
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql.type_api import TypeEngine

from .serialize import ContextScalar

type ContextAnnotation = type | types.UnionType | types.GenericAlias

_SCALAR_TYPES: dict[type[ContextScalar], TypeEngine[ContextScalar]] = {
    bool: cast(TypeEngine[ContextScalar], sa.Boolean()),
    int: cast(TypeEngine[ContextScalar], sa.BigInteger()),
    float: cast(TypeEngine[ContextScalar], sa.Double()),
    str: cast(TypeEngine[ContextScalar], sa.Text()),
    uuid.UUID: cast(TypeEngine[ContextScalar], sa.Uuid()),
    datetime.datetime: cast(TypeEngine[ContextScalar], sa.DateTime(timezone=True)),
    datetime.date: cast(TypeEngine[ContextScalar], sa.Date()),
}


def sql_type(annotation: ContextAnnotation) -> TypeEngine[ContextScalar]:
    """Derive the PostgreSQL cast for one context field annotation."""
    if isinstance(annotation, types.UnionType):
        candidates = [arm for arm in typing.get_args(annotation) if arm is not types.NoneType]
        if len(candidates) != 1:
            raise TypeError(f"context fields accept one optional type, got {annotation!r}")
        return sql_type(candidates[0])
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated:
        return sql_type(typing.get_args(annotation)[0])
    if origin in {frozenset, list, set, tuple}:
        item, *rest = typing.get_args(annotation)
        if origin is tuple and rest != [Ellipsis]:
            raise TypeError("context tuples must be homogeneous, like tuple[UUID, ...]")
        if origin is not tuple and rest:
            raise TypeError("context collections take one item type")
        return cast(TypeEngine[ContextScalar], ARRAY[ContextScalar](sql_type(item)))
    if (
        typing.is_typeddict(annotation)
        or origin is dict
        or isinstance(annotation, type)
        and issubclass(annotation, BaseModel)
    ):
        return cast(TypeEngine[ContextScalar], JSONB())
    if isinstance(annotation, type) and annotation in _SCALAR_TYPES:
        return _SCALAR_TYPES[annotation]
    raise TypeError(f"no PostgreSQL cast for context annotation {annotation!r}")

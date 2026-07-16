from functools import cached_property
from typing import ClassVar
from typing import cast

import inflection
from patos import FrozenModel
from sqlalchemy.sql.elements import ColumnElement

from .guc import current_setting
from .guc import valid_setting_name
from .serialize import ContextScalar
from .serialize import serialize
from .types import ContextAnnotation
from .types import sql_type

INFO_KEY = "rls.context"


class Context(FrozenModel):
    """Typed transaction-local PostgreSQL settings with derived names.

    Field names are the setting names, annotations derive the SQL casts, and the setting
    prefix snake-cases from the class name unless passed explicitly. Instances carry values
    while `setting` builds the matching policy-side SQL expression.

    ```python
    class ScopeTable(FrozenModel):
        read: frozenset[uuid.UUID] = frozenset()

    class User(rls.Context, prefix="app"):
        scopes: ScopeTable = ScopeTable()

    read = sa.func.to_jsonb(table.c.scopes).op("<@")(User.setting("scopes").op("->")("read"))
    async with sessions(info=User(scopes=ScopeTable(read=...)).info()):
    ```
    """

    __namespace__: ClassVar[str]

    def __init_subclass__(cls, prefix: str | None = None) -> None:
        super().__init_subclass__()
        cls.__namespace__ = prefix or inflection.underscore(cls.__name__)
        if not valid_setting_name(cls.__namespace__):
            raise ValueError(f"invalid PostgreSQL setting namespace {cls.__namespace__!r}")

    @classmethod
    def setting(cls, name: str) -> ColumnElement[ContextScalar]:
        """Return one declared field as a typed transaction-local SQL setting."""
        field = cls.__pydantic_fields__[name]
        if field.exclude:
            raise AttributeError(f"{name} is not a PostgreSQL setting")
        annotation = cast(ContextAnnotation, field.annotation)
        return current_setting(name, sql_type(annotation), prefix=cls.__namespace__)

    def info(self) -> dict[str, "Context"]:
        """Build the `Session.info` payload that binds this context per transaction."""
        return {INFO_KEY: self}

    @cached_property
    def settings(self) -> tuple[tuple[str, str], ...]:
        """Serialize every field once as `(qualified name, text)` pairs."""
        return tuple(
            (f"{type(self).__namespace__}.{name}", serialize(getattr(self, name)))
            for name, field in type(self).__pydantic_fields__.items()
            if not field.exclude
        )

from functools import cached_property
from typing import ClassVar
from typing import cast

import inflection
from patos import FrozenModel
from pydantic import BaseModel
from sqlalchemy.sql.elements import ColumnElement

from ..exceptions import ContextError
from .guc import current_setting
from .guc import is_valid_setting_name
from .serialize import ContextScalar
from .serialize import serialize
from .session import SessionContext
from .types import ContextAnnotation
from .types import sql_type


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

    read = table.c.scopes.op("<@")(User.setting("scopes.read"))
    async with sessions(info=User(scopes=ScopeTable(read=...)).info()):
    ```
    """

    __namespace__: ClassVar[str]

    def __init_subclass__(cls, prefix: str | None = None) -> None:
        super().__init_subclass__()
        cls.__namespace__ = prefix or inflection.underscore(cls.__name__)
        if not is_valid_setting_name(cls.__namespace__):
            raise ContextError(f"invalid PostgreSQL setting namespace {cls.__namespace__!r}")

    @cached_property
    def settings(self) -> tuple[tuple[str, str], ...]:
        """Serialize every scalar leaf once as `(qualified name, text)` pairs."""
        values: list[tuple[str, str]] = []

        def collect(model: BaseModel, path: tuple[str, ...] = ()) -> None:
            for name, field in type(model).__pydantic_fields__.items():
                if field.exclude:
                    continue
                value = getattr(model, name)
                nested = (*path, name)
                if isinstance(value, BaseModel):
                    collect(value, nested)
                else:
                    qualified = ".".join((type(self).__namespace__, *nested))
                    values.append((qualified, serialize(value)))

        collect(self)
        return tuple(values)

    @classmethod
    def setting(cls, name: str) -> ColumnElement[ContextScalar]:
        """Return one declared field as a typed transaction-local SQL setting."""

        def resolve(model: type[BaseModel], parts: tuple[str, ...]) -> ContextAnnotation:
            part, *remaining = parts
            try:
                field = model.__pydantic_fields__[part]
            except KeyError as missing:
                raise AttributeError(f"{name} is not a PostgreSQL setting") from missing
            if field.exclude:
                raise AttributeError(f"{name} is not a PostgreSQL setting")
            annotation = cast(ContextAnnotation, field.annotation)
            if not remaining:
                if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                    raise AttributeError(f"{name} is a setting group, choose one of its fields")
                return annotation
            if not isinstance(annotation, type) or not issubclass(annotation, BaseModel):
                raise AttributeError(f"{name} is not a PostgreSQL setting")
            return resolve(annotation, tuple(remaining))

        annotation = resolve(cls, tuple(name.split(".")))
        return current_setting(name, sql_type(annotation), prefix=cls.__namespace__)

    def info(self) -> dict[str, SessionContext]:
        """Build the `Session.info` payload that binds this context per transaction."""
        return SessionContext(self.settings).info()

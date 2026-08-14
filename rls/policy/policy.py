from typing import Self

import pydantic
from patos import FrozenFlexModel

from .command import Command
from .compiled import CompiledPolicy
from .predicate import Predicate
from .predicate import compile_expression


class Policy(FrozenFlexModel):
    """One declarative PostgreSQL row security policy."""

    command: Command
    using: Predicate | None = None
    check: Predicate | None = None
    roles: tuple[str, ...] = ("public",)
    permissive: bool = True
    name: str | None = None

    @property
    def resolved_name(self) -> str:
        """Return the explicit name or the table-local command default."""
        return self.name or f"rls_{self.command.value}"

    @classmethod
    def delete(
        cls,
        using: Predicate,
        *,
        name: str | None = None,
        roles: tuple[str, ...] = ("public",),
        permissive: bool = True,
    ) -> Self:
        """Build a `DELETE` policy."""
        return cls(
            name=name,
            command=Command.delete,
            using=using,
            roles=roles,
            permissive=permissive,
        )

    @classmethod
    def for_all(
        cls,
        using: Predicate,
        check: Predicate | None = None,
        *,
        name: str | None = None,
        roles: tuple[str, ...] = ("public",),
        permissive: bool = True,
    ) -> Self:
        """Build an `ALL` policy."""
        return cls(
            name=name,
            command=Command.all,
            using=using,
            check=check,
            roles=roles,
            permissive=permissive,
        )

    @classmethod
    def insert(
        cls,
        check: Predicate,
        *,
        name: str | None = None,
        roles: tuple[str, ...] = ("public",),
        permissive: bool = True,
    ) -> Self:
        """Build an `INSERT` policy."""
        return cls(
            name=name,
            command=Command.insert,
            check=check,
            roles=roles,
            permissive=permissive,
        )

    @classmethod
    def select(
        cls,
        using: Predicate,
        *,
        name: str | None = None,
        roles: tuple[str, ...] = ("public",),
        permissive: bool = True,
    ) -> Self:
        """Build a `SELECT` policy."""
        return cls(
            name=name,
            command=Command.select,
            using=using,
            roles=roles,
            permissive=permissive,
        )

    @classmethod
    def update(
        cls,
        using: Predicate,
        *,
        check: Predicate,
        name: str | None = None,
        roles: tuple[str, ...] = ("public",),
        permissive: bool = True,
    ) -> Self:
        """Build an `UPDATE` policy."""
        return cls(
            name=name,
            command=Command.update,
            using=using,
            check=check,
            roles=roles,
            permissive=permissive,
        )

    def compile(self) -> CompiledPolicy:
        """Compile this policy for migrations and catalog comparison."""
        return CompiledPolicy(
            name=self.resolved_name,
            command=self.command,
            using=compile_expression(self.using) if self.using is not None else None,
            check=compile_expression(self.check) if self.check is not None else None,
            roles=self.roles,
            permissive=self.permissive,
        )

    @pydantic.model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.name == "":
            raise ValueError("policy name cannot be empty")
        if not self.roles:
            raise ValueError("policy roles cannot be empty")
        self.command.using.check(self.command, "USING", self.using)
        self.command.checking.check(self.command, "WITH CHECK", self.check)
        return self

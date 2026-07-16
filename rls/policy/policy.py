from typing import Self

import pydantic
from patos import FrozenFlexModel

from .command import Command
from .compiled import CompiledPolicy
from .predicate import Predicate
from .predicate import compile_expression


class Policy(FrozenFlexModel):
    """One declarative PostgreSQL row security policy."""

    name: str
    command: Command
    using: Predicate | None = None
    check: Predicate | None = None
    roles: tuple[str, ...] = ("public",)
    permissive: bool = True

    @pydantic.model_validator(mode="after")
    def validate_shape(self) -> Self:
        if not self.name:
            raise ValueError("policy name cannot be empty")
        if not self.roles:
            raise ValueError("policy roles cannot be empty")
        self.command.using.check(self.command, "USING", self.using)
        self.command.checking.check(self.command, "WITH CHECK", self.check)
        return self

    @classmethod
    def select(
        cls,
        name: str,
        using: Predicate,
        *,
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
    def insert(
        cls,
        name: str,
        check: Predicate,
        *,
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
    def update(
        cls,
        name: str,
        using: Predicate,
        check: Predicate,
        *,
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

    @classmethod
    def delete(
        cls,
        name: str,
        using: Predicate,
        *,
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
        name: str,
        using: Predicate,
        check: Predicate | None = None,
        *,
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

    def compile(self) -> CompiledPolicy:
        """Compile this policy for migrations and catalog comparison."""
        return CompiledPolicy(
            name=self.name,
            command=self.command,
            using=compile_expression(self.using) if self.using is not None else None,
            check=compile_expression(self.check) if self.check is not None else None,
            roles=self.roles,
            permissive=self.permissive,
        )

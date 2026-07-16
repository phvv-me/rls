from functools import partial
from typing import Self

import sqlglot
from patos import FrozenModel
from sqlglot import exp
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from .command import Command


class CompiledPolicy(FrozenModel):
    """A policy with PostgreSQL predicates ready for migration source."""

    name: str
    command: Command
    using: str | None = None
    check: str | None = None
    roles: tuple[str, ...] = ("public",)
    permissive: bool = True

    @staticmethod
    def _rewrite(node: exp.Expr, table: str) -> exp.Expr:
        """Canonicalize one PostgreSQL deparser AST node."""
        if isinstance(node, (exp.Cast, exp.TryCast)):
            if isinstance(node.this, (exp.Cast, exp.TryCast)):
                inner_target = node.this.args.get("to")
                if (
                    isinstance(node.this.this, exp.JSONExtractScalar)
                    and isinstance(inner_target, exp.DataType)
                    and inner_target.this is exp.DataType.Type.TEXT
                ):
                    rewritten = node.copy()
                    rewritten.set("this", node.this.this.copy())
                    return rewritten
            target = node.args.get("to")
            if (
                (
                    isinstance(node.this, (exp.JSONExtract, exp.JSONExtractScalar))
                    or isinstance(node.this, exp.Literal)
                    and node.this.is_string
                )
                and isinstance(target, exp.DataType)
                and target.this is exp.DataType.Type.TEXT
            ):
                return node.this
        if isinstance(node, exp.Subquery) and isinstance(node.this, exp.Subquery):
            return node.this
        if (
            isinstance(node, exp.Subquery)
            and isinstance(node.parent, exp.Array)
            and isinstance(node.this, exp.Expr)
        ):
            return node.this
        if isinstance(node, exp.Paren) and isinstance(node.this, exp.Expr):
            return node.this
        if isinstance(node, exp.EQ):
            target = node.expression
            if isinstance(target, exp.Any) and isinstance(target.this, exp.Array):
                return exp.In(this=node.this.copy(), expressions=target.this.expressions)
        if isinstance(node, exp.Column) and node.table.casefold() == table.casefold():
            return exp.column(node.this.copy())
        return node

    @classmethod
    def _normalize(cls, clause: str | None, table: str) -> str | None:
        """Remove PostgreSQL deparser noise without changing predicate meaning."""
        if clause is None:
            return None
        tree = sqlglot.parse_one(clause, dialect="postgres")
        tree = exp.replace_tree(tree, partial(cls._rewrite, table=table))
        normalize_identifiers(tree, dialect="postgres")
        return tree.sql(dialect="postgres")

    def normalized(self, table: str) -> Self:
        """Return the canonical value used for catalog comparison."""
        return self.model_copy(
            update={
                "using": self._normalize(self.using, table),
                "check": self._normalize(self.check, table),
                "roles": tuple(sorted(set(self.roles))),
            }
        )

    def matches(self, live: Self, table: str) -> bool:
        """Whether a reflected policy is semantically the same policy."""
        return self.normalized(table) == live.normalized(table)

from functools import partial
from re import compile
from typing import Self

import sqlglot
from patos import FrozenModel
from sqlglot import exp
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from .command import Command

_DOLLAR_QUOTE = compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


class CompiledPolicy(FrozenModel):
    """A policy with PostgreSQL predicates ready for migration source."""

    name: str
    command: Command
    using: str | None = None
    check: str | None = None
    roles: tuple[str, ...] = ("public",)
    permissive: bool = True

    def matches(self, live: Self, table: str) -> bool:
        """Whether a reflected policy is semantically the same policy."""
        return self.normalized(table) == live.normalized(table)

    def normalized(self, table: str) -> Self:
        """Return the canonical value used for catalog comparison."""
        return self.model_copy(
            update={
                "using": self._normalize(self.using, table),
                "check": self._normalize(self.check, table),
                "roles": tuple(sorted(set(self.roles))),
            }
        )

    @staticmethod
    def _rewrite(node: exp.Expr, table: str) -> exp.Expr:
        """Canonicalize one PostgreSQL deparser AST node."""
        if isinstance(node, (exp.Cast, exp.TryCast)):
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
            if (
                isinstance(node.this, exp.Literal)
                and node.this.is_number
                and isinstance(target, exp.DataType)
                and target.this
                in {
                    exp.DataType.Type.SMALLINT,
                    exp.DataType.Type.INT,
                    exp.DataType.Type.BIGINT,
                }
            ):
                return node.this
        if isinstance(node, exp.Subquery) and isinstance(node.this, exp.Subquery):
            return node.this
        if (
            isinstance(node, exp.Dot)
            and isinstance(node.this, exp.Identifier)
            and node.this.name.casefold() == "public"
            and isinstance(node.expression, exp.Anonymous)
        ):
            return node.expression
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
        tree = sqlglot.parse_one(cls._postgres_casts(clause), dialect="postgres")
        tree = exp.replace_tree(tree, partial(cls._rewrite, table=table))
        normalize_identifiers(tree, dialect="postgres")
        return tree.sql(dialect="postgres")

    @classmethod
    def _postgres_casts(cls, clause: str) -> str:
        """Translate CockroachDB triple-colon casts without touching quoted text."""
        normalized: list[str] = []
        quote: str | None = None
        index = 0
        while index < len(clause):
            if quote is not None:
                if clause.startswith(quote, index):
                    normalized.append(quote)
                    index += len(quote)
                    if quote in {"'", '"'} and clause.startswith(quote, index):
                        normalized.append(quote)
                        index += len(quote)
                    else:
                        quote = None
                else:
                    normalized.append(clause[index])
                    index += 1
                continue
            if clause.startswith(":::", index):
                normalized.append("::")
                index += 3
                continue
            if clause[index] in {"'", '"'}:
                quote = clause[index]
            elif dollar_quote := _DOLLAR_QUOTE.match(clause, index):
                quote = dollar_quote.group()
                normalized.append(quote)
                index += len(quote)
                continue
            normalized.append(clause[index])
            index += 1
        return "".join(normalized)

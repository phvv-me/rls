"""Canonicalize a compiled policy clause and a catalog-deparsed one so drift only ever means drift.

Ported from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls), whose own
`_sql_gen.normalize_sql_policy_expression` folded case, whitespace, and cast spelling with regex
substitutions on the raw text. This port replaces that regex pass with an AST-level normalization
through `sqlglot`: both the freshly compiled expression and the text Postgres hands back from
`pg_policies.qual`/`with_check` are parsed, folded to a common shape, and re-serialized, so the
comparison survives every re-serialization Postgres is free to perform (reparenthesizing, rewriting
`IN (...)` as `= ANY (ARRAY[...])`, adding or dropping a `::type` cast) without also silently
swallowing a real change in meaning: a token-level fold on the *parsed structure*, not on
arbitrary substrings, and a single explicit list of the transforms it applies.
"""

import sqlglot
from sqlglot import exp

_DIALECT = "postgres"


def _swap(tree: exp.Expr, old: exp.Expr, new: exp.Expr) -> exp.Expr:
    """Replace `old` with `new` inside `tree`, returning the new root when `old` was the root.

    `Expression.replace` is a no-op on a node with no parent, so a match at the very top of the
    tree (a whole clause that is itself one cast, or a bare `= ANY (...)`) has to swap the root
    reference this function returns instead of mutating in place.

    tree: the current root of the expression being normalized.
    old: node being folded away, already found inside `tree`.
    new: replacement node.
    """
    if old is tree:
        return new
    old.replace(new)
    return tree


def _strip_casts(tree: exp.Expr) -> exp.Expr:
    """Drop every `CAST(x AS t)`/`x::t` down to its inner `x`, casts carry no comparable meaning.

    A stored policy's `::uuid`/`::text` casts and an equivalent hand-written `CAST(... AS uuid)`
    compile to different AST shapes for the identical runtime check, and Postgres is free to
    re-spell one as the other on deparse, so neither survives as a comparable token here.
    """
    for node in list(tree.find_all(exp.Cast, exp.TryCast)):
        tree = _swap(tree, node, node.this)
    return tree


def _strip_parens(tree: exp.Expr) -> exp.Expr:
    """Drop every redundant grouping `Paren` node, Postgres reflows parenthesization freely.

    `sqlglot`'s tree already encodes operator precedence structurally, so a `Paren` wrapper adds no
    information the comparison needs; leaving it in would make `(a = b)` and `a = b` compare unequal
    for no semantic reason.
    """
    for node in list(tree.find_all(exp.Paren)):
        tree = _swap(tree, node, node.this)
    return tree


def _fold_any_array(tree: exp.Expr) -> exp.Expr:
    """Fold `x = ANY (ARRAY[a, b])` to `x IN (a, b)`, the shape a freshly compiled `.in_(...)` uses.

    Postgres always deparses a stored `col IN (a, b)` policy as the equivalent
    `ScalarArrayOpExpr`, `col = ANY (ARRAY[a, b])`, never as the literal `IN` syntax the clause was
    written with, so without this fold every `IN` predicate would read as permanently drifted
    against its own unchanged self. Only the `= ANY (ARRAY[...])` shape folds; `= ANY (<subquery>)`
    is left alone since it has no `IN (...)` equivalent to begin with.
    """
    for node in list(tree.find_all(exp.EQ)):
        target = node.expression
        if isinstance(target, exp.Any) and isinstance(target.this, exp.Array):
            folded = exp.In(this=node.this.copy(), expressions=target.this.expressions)
            tree = _swap(tree, node, folded)
    return tree


def _unqualify(tree: exp.Expr, table: str) -> exp.Expr:
    """Strip `table.` qualification from every column reference naming the policy's own table.

    Postgres deparses a policy's own target-table columns unqualified (there is only ever one such
    table in scope at the clause's top level) while keeping a correlated subquery's columns
    qualified; a freshly compiled expression built from a real mapped ORM column instead of a bare
    `sqlalchemy.column()` stand-in carries that qualification, so it has to be dropped for the two
    textual forms to compare equal.

    table: name of the table the policy protects; only columns qualified by this exact name fold.
    """
    for node in list(tree.find_all(exp.Column)):
        if node.table and node.table.lower() == table.lower():
            tree = _swap(tree, node, exp.column(node.this.copy()))
    return tree


def normalize_expression(expression: str, table: str | None = None) -> str:
    """Fold a compiled or catalog-read clause to a form comparable across re-serializations.

    expression: `qual`/`with_check` text, either freshly compiled or read back from `pg_policies`.
    table: the policy's own target table, when known, so self-table qualification also folds away.
    """
    tree: exp.Expr = sqlglot.parse_one(expression, dialect=_DIALECT)
    tree = _strip_casts(tree)
    tree = _strip_parens(tree)
    tree = _fold_any_array(tree)
    if table is not None:
        tree = _unqualify(tree, table)
    return tree.sql(dialect=_DIALECT).lower()

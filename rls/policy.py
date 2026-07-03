"""The declared shape of one row-level-security policy, and its compiled and DDL forms.

Ported from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls), whose `Policy` accepted a
`cmd` of `Command | list[Command]` including a catch-all `Command.all`, generating one `FOR ALL`
policy whose `USING` clause is also OR-ed into a table's `SELECT` visibility by Postgres, letting a
write predicate leak into read visibility. `Command` here drops `ALL` entirely: a table that needs
several commands guarded declares one `Policy` per command instead, so nothing is ever visible
through a write-only clause. `Policy.using`/`Policy.check` also split what upstream folded into one
`custom_expr` callable, matching how Postgres itself distinguishes the `USING` clause (checked
against existing rows) from `WITH CHECK` (checked against the row a write would leave behind).
"""

from enum import StrEnum

import pydantic
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.elements import ColumnElement


class Command(StrEnum):
    """The single SQL command one policy guards, never `ALL`.

    https://www.postgresql.org/docs/current/sql-createpolicy.html enumerates `ALL` as a valid
    policy command, but a `FOR ALL` policy's `USING` clause is also applied to `SELECT`, so a
    write predicate narrower than the read predicate would leak past it. A table that needs several
    commands guarded declares one `Policy` per command instead.
    """

    select = "SELECT"
    insert = "INSERT"
    update = "UPDATE"
    delete = "DELETE"


class Policy(pydantic.BaseModel):
    """One `CREATE POLICY` a caller declares, its clauses live SQLAlchemy boolean expressions.

    name: policy name, unique per table.
    command: the single command this policy guards.
    using: the `USING` clause, checked against every existing row a `SELECT`, `UPDATE`, or `DELETE`
        may touch. Absent for `INSERT`, which has no existing row to guard.
    check: the `WITH CHECK` clause, checked against the row an `INSERT` or `UPDATE` would leave
        behind. Absent for `SELECT` and `DELETE`, which write nothing.
    """

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str
    command: Command
    using: ColumnElement | None = None
    check: ColumnElement | None = None


class CompiledPolicy(pydantic.BaseModel):
    """A `Policy` with its clauses already rendered to literal-inlined Postgres text.

    The shape an Alembic migration file actually stores: a migration is plain text read back years
    later, so its ops carry compiled SQL strings rather than live `ColumnElement` objects tied to
    the model metadata current when the migration was generated.
    """

    model_config = pydantic.ConfigDict(frozen=True)

    name: str
    command: Command
    using: str | None = None
    check: str | None = None


def compile_expression(expression: ColumnElement) -> str:
    """Render a boolean SQLAlchemy expression to the literal-inlined Postgres text a policy stores.

    A `CREATE POLICY` clause takes no bind parameters, so every literal a comparison carries, a
    role name or a cast target, is inlined rather than left as a placeholder; `literal_binds` is the
    compiler flag that does the inlining.

    expression: the clause to compile, typically built from GUC reads and a table's own columns.
    """
    return str(
        expression.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    )


def compile_policy(policy: Policy) -> CompiledPolicy:
    """Compile a declared `Policy`'s live expressions into a migration-storable `CompiledPolicy`.

    policy: the declared policy, its clauses SQLAlchemy expressions over a table's own columns.
    """
    return CompiledPolicy(
        name=policy.name,
        command=policy.command,
        using=compile_expression(policy.using) if policy.using is not None else None,
        check=compile_expression(policy.check) if policy.check is not None else None,
    )


def create_statement(table: str, policy: CompiledPolicy) -> str:
    """The `CREATE POLICY` statement for one compiled policy on `table`.

    table: table the policy protects.
    policy: the compiled policy, already carrying literal-inlined clause text.
    """
    clause = ""
    if policy.using is not None:
        clause += f" USING ({policy.using})"
    if policy.check is not None:
        clause += f" WITH CHECK ({policy.check})"
    return f"CREATE POLICY {policy.name} ON {table} FOR {policy.command.value}{clause}"


def drop_statement(table: str, name: str) -> str:
    """The `DROP POLICY IF EXISTS` statement removing one named policy from `table`.

    table: table the policy currently protects.
    name: name of the policy to drop.
    """
    return f"DROP POLICY IF EXISTS {name} ON {table}"


def enable_statements(
    table: str, policies: list[CompiledPolicy], grant_role: str | None = None
) -> list[str]:
    """The enable, force, and per-policy DDL that protects `table`, in declaration order.

    Force is unconditional: a table without `FORCE ROW LEVEL SECURITY` still leaks every row to
    its own owning role, since row level security only ever binds non-owner callers by default,
    the gap upstream's separate `create_policies()` path closed but its Alembic path never did.

    table: table to protect.
    policies: compiled policies to create, in the order they should be declared.
    grant_role: also grant this role `SELECT, INSERT, UPDATE, DELETE` on `table`, skipped when
        `None`, e.g. while the role does not exist yet during an early bootstrap migration.
    """
    statements = [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        *(create_statement(table, policy) for policy in policies),
    ]
    if grant_role is not None:
        statements.append(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {grant_role}")
    return statements


def disable_statements(
    table: str, policies: list[CompiledPolicy], grant_role: str | None = None
) -> list[str]:
    """Reverse `enable_statements` for `table`, dropping every policy in reverse order.

    table: table to unprotect.
    policies: compiled policies to drop, in the same order `enable_statements` created them.
    grant_role: also revoke this role's grant on `table`, matching how `enable_statements` granted
        it.
    """
    statements = [drop_statement(table, policy.name) for policy in reversed(policies)]
    statements += [
        f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
    ]
    if grant_role is not None:
        statements.insert(0, f"REVOKE ALL ON {table} FROM {grant_role}")
    return statements

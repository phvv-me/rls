"""Read the live catalog back and check it still satisfies a declared row-level-security registry.

New in this port: upstream (DelfinaCare/rls, MIT) had no equivalent, its Alembic comparator diffed
the catalog only to plan the next migration, never to answer "is the live schema correct right now,
independent of any pending migration". These functions serve that second question directly, so a
CI check or a startup guard can call `verify_rls` and fail loud the moment a declared policy and
the live catalog disagree, whether from a hand-run `ALTER TABLE` a migration never saw or a
migration that silently failed partway through.
"""

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.sql.elements import ColumnElement

from .normalize import normalize_expression
from .policy import Command
from .policy import CompiledPolicy
from .policy import Policy
from .policy import compile_expression
from .registry import declared_policies


def live_security(connection: Connection, tables: set[str]) -> dict[str, tuple[bool, bool]]:
    """Live `(force, enabled)` row security flags per table, a missing table absent from the dict.

    connection: synchronous connection used to read the catalog.
    tables: table names to read the flags for.
    """
    return {
        name: (force, enabled)
        for name, force, enabled in connection.execute(
            text(
                "SELECT c.relname, c.relforcerowsecurity, c.relrowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relname = ANY(:tables)"
            ),
            {"tables": sorted(tables)},
        )
    }


def live_policies(
    connection: Connection, tables: set[str]
) -> dict[tuple[str, str], tuple[str, str | None, str | None]]:
    """Live `(table, policyname) -> (cmd, qual, with_check)` for every policy on `tables`.

    connection: synchronous connection used to read the catalog.
    tables: table names to read policies for.
    """
    return {
        (table, name): (cmd, qual, with_check)
        for table, name, cmd, qual, with_check in connection.execute(
            text(
                "SELECT tablename, policyname, cmd, qual, with_check FROM pg_policies "
                "WHERE schemaname = 'public' AND tablename = ANY(:tables)"
            ),
            {"tables": sorted(tables)},
        )
    }


def clause_matches(
    declared_clause: ColumnElement | None, live_clause: str | None, table: str
) -> bool:
    """Whether one live `USING` or `WITH CHECK` clause still matches its declared counterpart.

    A declared clause absent from the policy (`SELECT` carries no `WITH CHECK`, `INSERT` no
    `USING`) matches only a live clause that is equally absent, so an unexpectedly present clause
    still counts as drift rather than a silent pass.

    declared_clause: the policy's own `USING` or `WITH CHECK` expression, `None` when the command
        omits it.
    live_clause: the catalog's `qual` or `with_check` text for the same clause.
    table: the policy's own target table, threaded through to `normalize_expression` so self-table
        qualification also folds away.
    """
    if declared_clause is None:
        return live_clause is None
    if live_clause is None:
        return False
    return normalize_expression(live_clause, table) == normalize_expression(
        compile_expression(declared_clause), table
    )


def policy_matches(
    declared: Policy, live: tuple[str, str | None, str | None] | None, table: str
) -> bool:
    """Whether a live catalog policy row still satisfies a declared policy's shape and clauses.

    declared: the policy a caller declared.
    live: the catalog's own `(cmd, qual, with_check)` for a same-named policy, or `None` when no
        policy by that name exists on the table at all.
    table: table the policy protects.
    """
    if live is None:
        return False
    cmd, qual, with_check = live
    return (
        cmd == declared.command.value
        and clause_matches(declared.using, qual, table)
        and clause_matches(declared.check, with_check, table)
    )


def unprotected_tables(connection: Connection, expected: set[str]) -> list[str]:
    """Expected tables the live schema never enabled and forced row security on at all.

    The coarse half of the drift check: a table missing here still needs its declared policies
    diffed by `drifted_policies`, but a table failing this check needs the whole-table
    `apply_rls` bootstrap instead, since an unforced or unenabled table has no reliable existing
    policy set to diff against.

    connection: synchronous connection used to read the catalog.
    expected: table names the registry declares policies for.
    """
    security = live_security(connection, expected)
    return sorted(table for table in expected if not all(security.get(table, (False, False))))


def drifted_policies(
    connection: Connection, table: str, declared: list[Policy]
) -> tuple[list[Policy], list[CompiledPolicy]]:
    """Declared policies the live table is missing or holds stale, and live policies to drop.

    Only meaningful for a table `unprotected_tables` already reports as force-and-enabled; called
    for an already-protected table whose individual policies may have drifted from their
    declaration since the table was first forced.

    connection: synchronous connection used to read the catalog.
    table: table to diff, already force-and-enabled.
    declared: the policies currently declared for `table`.
    """
    live = live_policies(connection, {table})
    declared_names = {policy.name for policy in declared}
    stale = [
        CompiledPolicy(name=name, command=Command(cmd), using=qual, check=with_check)
        for (tbl, name), (cmd, qual, with_check) in live.items()
        if tbl == table and name not in declared_names
    ]
    changed = [
        policy
        for policy in declared
        if not policy_matches(policy, live.get((table, policy.name)), table)
    ]
    return changed, stale


def verify_rls(
    connection: Connection, expected: set[str], declared: dict[str, list[Policy]]
) -> list[str]:
    """Reasons the live schema fails the declared row-level-security contract for any table.

    Each table in `expected` must enable and force row security and carry every policy `declared`
    lists for it, with that policy's command and clauses still matching, normalized so a catalog
    re-serialization never counts as drift on its own. A clean schema returns an empty list, so a
    caller treats a non-empty result as a failure listing exactly what regressed.

    connection: synchronous connection used to read the catalog.
    expected: table names to verify.
    declared: `table -> policies` to verify against.
    """
    security = live_security(connection, expected)
    live_by_policy = live_policies(connection, expected)
    violations: list[str] = []
    for table in sorted(expected):
        force, enabled = security.get(table, (False, False))
        if not enabled:
            violations.append(f"{table}: row level security not enabled")
        if not force:
            violations.append(f"{table}: row level security not forced")
        for declared_policy in declared.get(table, []):
            live = live_by_policy.get((table, declared_policy.name))
            if policy_matches(declared_policy, live, table):
                continue
            if live is None:
                violations.append(f"{table}: missing {declared_policy.name} policy")
            elif live[0] != declared_policy.command.value:
                violations.append(
                    f"{table}: {declared_policy.name} guards {live[0]!r}, "
                    f"expected {declared_policy.command.value!r}"
                )
            else:
                violations.append(
                    f"{table}: {declared_policy.name} clause does not scope correctly"
                )
    return violations


def verify_scoped_rls(
    connection: Connection,
    expected: set[str],
    declared: dict[str, list[Policy]] | None = None,
) -> list[str]:
    """Reasons the live schema fails the no-leak contract for any expected table.

    A thin default over `verify_rls`: with no explicit `declared` it reads the merged policy set
    every registered metadata declares (`rls.registry.declared_policies`), so a caller checks the
    live catalog against exactly what `register()` opted in without threading the registry through
    by hand.

    connection: synchronous connection used to read the catalog.
    expected: table names to verify, typically a metadata's own `info["rls"]` set.
    declared: `table -> policies` to verify against, the merged registered registry by default; a
        test passes its own mapping to verify a synthetic table carrying no registered model.
    """
    registry = declared if declared is not None else declared_policies()
    return verify_rls(connection, expected, declared=registry)

from sqlalchemy import Table
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.schema import ExecutableDDLElement
from sqlalchemy.sql.compiler import DDLCompiler

from ..policy import CompiledPolicy
from .action import RLSAction


class RLSStatement(ExecutableDDLElement):
    """One typed row security DDL statement."""

    inherit_cache = False

    def __init__(
        self,
        table: Table,
        action: RLSAction,
        *,
        policy: CompiledPolicy | None = None,
        name: str | None = None,
    ) -> None:
        if action is RLSAction.create and policy is None:
            raise ValueError("create requires a compiled policy")
        if action is RLSAction.drop and name is None:
            raise ValueError("drop requires a policy name")
        self.table = table
        self.action = action
        self.policy = policy
        self.name = name


@compiles(RLSStatement, "postgresql")
def compile_statement(element: RLSStatement, compiler: DDLCompiler, **kwargs: bool) -> str:
    """Compile row security DDL with dialect-quoted identifiers."""
    del kwargs
    quote = compiler.preparer.quote
    table = compiler.preparer.format_table(element.table)
    policy = element.policy
    raw_name = policy.name if policy is not None else element.name
    name = quote(raw_name) if raw_name is not None else ""
    return element.action.value.format(
        table=table,
        name=name,
        mode=("PERMISSIVE" if policy is not None and policy.permissive else "RESTRICTIVE"),
        command=(policy.command.sql if policy is not None else ""),
        roles=(", ".join(quote(role) for role in policy.roles) if policy is not None else ""),
        using=(f" USING ({policy.using})" if policy is not None and policy.using else ""),
        check=(f" WITH CHECK ({policy.check})" if policy is not None and policy.check else ""),
    )

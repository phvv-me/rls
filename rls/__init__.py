"""Declarative PostgreSQL row level security for SQLAlchemy and Alembic.

Forked from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls; see `LICENSE`) and reworked
from the ground up: `FORCE ROW LEVEL SECURITY` is emitted on every path, not only the direct
`create_policies` one; a policy guards exactly one SQL command rather than a leaky `FOR ALL`; the
GUC namespace is a parameter, not a hardcoded `rls.` prefix; no bypass escape is baked into a
policy unless it opts in explicitly; there is no `starlette`/FastAPI dependency; and the Alembic
comparator canonicalizes a catalog's deparsed clause through `sqlglot` before diffing it against a
freshly compiled one, rather than a hand-rolled regex fold.

Importing this package registers its Alembic operations, comparator, and renderers as a side
effect, the contract any `env.py` that imports `rls` before running autogenerate relies on. Call
`register(Base)` once per declarative base during application setup so its `__rls_policies__` are
read as classes are mapped.
"""

from . import ops as ops
from .create import create_policies
from .guc import bypass_clause
from .guc import current_setting
from .normalize import normalize_expression
from .policy import Command
from .policy import CompiledPolicy
from .policy import Policy
from .policy import compile_expression
from .policy import compile_policy
from .policy import create_statement
from .policy import disable_statements
from .policy import drop_statement
from .policy import enable_statements
from .register import register
from .session import AsyncRlsSession
from .session import RlsSession
from .sessioner import AsyncRlsSessioner
from .sessioner import ContextGetter
from .sessioner import RlsSessioner
from .verify import clause_matches
from .verify import drifted_policies
from .verify import live_policies
from .verify import live_security
from .verify import policy_matches
from .verify import unprotected_tables
from .verify import verify_rls
from .views import security_invoker_view

__all__ = [
    "AsyncRlsSession",
    "AsyncRlsSessioner",
    "Command",
    "CompiledPolicy",
    "ContextGetter",
    "Policy",
    "RlsSession",
    "RlsSessioner",
    "bypass_clause",
    "clause_matches",
    "compile_expression",
    "compile_policy",
    "create_policies",
    "create_statement",
    "current_setting",
    "disable_statements",
    "drifted_policies",
    "drop_statement",
    "enable_statements",
    "live_policies",
    "live_security",
    "normalize_expression",
    "ops",
    "policy_matches",
    "register",
    "security_invoker_view",
    "unprotected_tables",
    "verify_rls",
]

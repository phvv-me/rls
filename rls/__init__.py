"""Declarative PostgreSQL row level security for SQLAlchemy and Alembic.

Forked from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls; see `LICENSE`) and reworked
from the ground up: `FORCE ROW LEVEL SECURITY` is emitted on every path, not only the direct
`create_policies` one; a policy guards exactly one SQL command rather than a leaky `FOR ALL`; the
GUC namespace is a parameter, not a hardcoded `rls.` prefix; no bypass escape is baked into a
policy unless it opts in explicitly; and the Alembic comparator canonicalizes a catalog's deparsed
clause through `sqlglot` before diffing it against a freshly compiled one, rather than a hand-rolled
regex fold.

The package reads by concern: `policy` holds the policy model and its compiled and DDL forms,
`session` the runtime session binding and GUC helpers, `schema` the declarative registration plus
the schema-application and verification wiring, and `ops` the Alembic autogenerate integration.
Every name below re-exports one of those, so `import rls` keeps its flat surface unchanged.

Importing this package registers its Alembic operations, comparator, and renderers as a side
effect, the contract any `env.py` that imports `rls` before running autogenerate relies on. Call
`register(Base)` once per declarative base during application setup so its `__rls_policies__` are
read as classes are mapped.
"""

from . import ops as ops
from .ops import ApplyScopedRlsOp
from .ops import CreatePolicyOp
from .ops import DropPolicyOp
from .ops import DropScopedRlsOp
from .ops import compare_scoped_rls
from .ops import render_apply_scoped_rls
from .ops import render_create_policy
from .ops import render_drop_policy
from .ops import render_drop_scoped_rls
from .ops import run_apply_scoped_rls
from .ops import run_create_policy
from .ops import run_drop_policy
from .ops import run_drop_scoped_rls
from .ops import scoped_apply_statements
from .ops import scoped_drop_statements
from .policy import Command
from .policy import CompiledPolicy
from .policy import Policy
from .policy import compile_expression
from .policy import compile_policy
from .policy import create_statement
from .policy import disable_statements
from .policy import drop_statement
from .policy import enable_statements
from .policy import normalize as normalize
from .policy import normalize_expression
from .schema import app_role_statements
from .schema import clause_matches
from .schema import create as create
from .schema import create_policies
from .schema import declared_policies
from .schema import drifted_policies
from .schema import live_policies
from .schema import live_security
from .schema import metadata_for_table
from .schema import policy_matches
from .schema import register
from .schema import registry as registry
from .schema import roles as roles
from .schema import security_invoker_view
from .schema import unprotected_tables
from .schema import verify as verify
from .schema import verify_rls
from .schema import verify_scoped_rls
from .schema import views as views
from .session import AsyncRlsSession
from .session import AsyncRlsSessioner
from .session import ContextGetter
from .session import RlsSession
from .session import RlsSessioner
from .session import bypass_clause
from .session import current_setting
from .session import guc as guc
from .session import sessioner as sessioner

# The three concern subpackages carry the flat-module names the public surface has always exposed
# (`rls.verify`, `rls.guc`, ...), re-bound above so `import rls; rls.verify.live_policies` still
# resolves. `schema` is the one grouping name new to this layout, so drop the binding the imports
# above leaked onto the package to keep `dir(rls)` exactly what consumers saw before the split.
globals().pop("schema", None)

__all__ = [
    "ApplyScopedRlsOp",
    "AsyncRlsSession",
    "AsyncRlsSessioner",
    "Command",
    "CompiledPolicy",
    "ContextGetter",
    "CreatePolicyOp",
    "DropPolicyOp",
    "DropScopedRlsOp",
    "Policy",
    "RlsSession",
    "RlsSessioner",
    "app_role_statements",
    "bypass_clause",
    "clause_matches",
    "compare_scoped_rls",
    "compile_expression",
    "compile_policy",
    "create_policies",
    "create_statement",
    "current_setting",
    "declared_policies",
    "disable_statements",
    "drifted_policies",
    "drop_statement",
    "enable_statements",
    "live_policies",
    "live_security",
    "metadata_for_table",
    "normalize_expression",
    "ops",
    "policy_matches",
    "register",
    "registry",
    "render_apply_scoped_rls",
    "render_create_policy",
    "render_drop_policy",
    "render_drop_scoped_rls",
    "run_apply_scoped_rls",
    "run_create_policy",
    "run_drop_policy",
    "run_drop_scoped_rls",
    "scoped_apply_statements",
    "scoped_drop_statements",
    "security_invoker_view",
    "unprotected_tables",
    "verify_rls",
    "verify_scoped_rls",
]

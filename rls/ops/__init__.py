"""The Alembic autogenerate integration: operations, their DDL, the comparator, and the renderer.

Split across four files so each Alembic hook this package plugs into lives on its own:
`operations.py` defines the `MigrateOperation` subclasses a migration calls, `implementations.py`
gives each one its DDL, `comparator.py` decides which ops a `revision --autogenerate` pass queues,
and `renderer.py` turns a queued op back into migration source. Importing this subpackage runs
every `register_operation`/`implementation_for`/`dispatch_for` decorator as a side effect, the
contract any `env.py` that imports `rls` before running autogenerate relies on.
"""

from . import comparator as comparator
from . import implementations as implementations
from . import scoped as scoped
from .comparator import compare_rls
from .implementations import run_apply_rls
from .implementations import run_create_policy
from .implementations import run_drop_policy
from .implementations import run_drop_rls
from .operations import ApplyRlsOp
from .operations import CreatePolicyOp
from .operations import DropPolicyOp
from .operations import DropRlsOp
from .operations import RLSOp
from .renderer import render_apply_rls
from .renderer import render_create_policy
from .renderer import render_drop_policy
from .renderer import render_drop_rls
from .scoped import ApplyScopedRlsOp
from .scoped import DropScopedRlsOp
from .scoped import compare_scoped_rls
from .scoped import render_apply_scoped_rls
from .scoped import render_drop_scoped_rls
from .scoped import run_apply_scoped_rls
from .scoped import run_drop_scoped_rls
from .scoped import scoped_apply_statements
from .scoped import scoped_drop_statements

__all__ = [
    "RLSOp",
    "ApplyRlsOp",
    "ApplyScopedRlsOp",
    "CreatePolicyOp",
    "DropPolicyOp",
    "DropRlsOp",
    "DropScopedRlsOp",
    "compare_rls",
    "compare_scoped_rls",
    "render_apply_rls",
    "render_apply_scoped_rls",
    "render_create_policy",
    "render_drop_policy",
    "render_drop_rls",
    "render_drop_scoped_rls",
    "run_apply_rls",
    "run_apply_scoped_rls",
    "run_create_policy",
    "run_drop_policy",
    "run_drop_rls",
    "run_drop_scoped_rls",
    "scoped_apply_statements",
    "scoped_drop_statements",
]

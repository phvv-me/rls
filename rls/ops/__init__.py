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
from .comparator import compare_rls
from .operations import ApplyRlsOp
from .operations import CreatePolicyOp
from .operations import DropPolicyOp
from .operations import DropRlsOp
from .operations import RLSOp
from .renderer import render_apply_rls
from .renderer import render_create_policy
from .renderer import render_drop_policy
from .renderer import render_drop_rls

__all__ = [
    "RLSOp",
    "ApplyRlsOp",
    "CreatePolicyOp",
    "DropPolicyOp",
    "DropRlsOp",
    "compare_rls",
    "render_apply_rls",
    "render_create_policy",
    "render_drop_policy",
    "render_drop_rls",
]

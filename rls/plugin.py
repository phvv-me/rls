import sys
from types import ModuleType

from alembic.runtime.plugins import Plugin
from alembic.util import DispatchPriority

from .alembic.autogen import compare_rls
from .alembic.operation import register_operations


def setup(plugin: Plugin) -> None:
    """Register PostgreSQL RLS comparison through Alembic's plugin-scoped API."""
    register_operations()
    plugin.add_autogenerate_comparator(
        compare_rls,
        "autogenerate",
        qualifier="postgresql",
        priority=DispatchPriority.LAST,
    )


plugins: tuple[ModuleType, ...] = (sys.modules[__name__],)

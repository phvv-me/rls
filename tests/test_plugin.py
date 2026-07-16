import importlib
import importlib.metadata
from typing import cast

import pytest
from alembic.autogenerate.api import AutogenContext
from alembic.operations.ops import UpgradeOps
from alembic.util import PriorityDispatchResult
from conftest import FakeAutogenContext
from conftest import FakeUpgradeOps

import rls


def test_version_falls_back_when_package_metadata_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing distribution leaves `__version__` at the sentinel, restored afterwards."""

    def raise_missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", raise_missing)
    importlib.reload(rls)
    assert rls.__version__ == "0.0.0"
    monkeypatch.undo()
    importlib.reload(rls)
    assert rls.__version__ != "0.0.0"


def test_plugin_comparator_delegates_after_alembic_is_ready() -> None:
    """Alembic is imported by now, so the lazy plugin entry point resolves and continues."""
    from rls.plugin import compare_rls

    context = cast(AutogenContext, FakeAutogenContext(None, None))
    operations = cast(UpgradeOps, FakeUpgradeOps())
    result = compare_rls(context, operations)
    assert result is PriorityDispatchResult.CONTINUE

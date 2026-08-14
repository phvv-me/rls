from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session
from sqlalchemy.orm import SessionTransaction

from ..exceptions import ContextError
from .guc import is_valid_qualified_setting_name

_INFO_KEY = "rls.context"


@dataclass(frozen=True, slots=True)
class SessionContext:
    """Serialized transaction settings independent of any application model library."""

    settings: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        names = [name for name, _ in self.settings]
        if invalid := [name for name in names if not is_valid_qualified_setting_name(name)]:
            raise ContextError(f"invalid PostgreSQL setting names {invalid!r}")
        if len(set(names)) != len(names):
            raise ContextError("PostgreSQL setting names must be unique")

    def info(self) -> dict[str, "SessionContext"]:
        """Build the standard `Session.info` payload for these settings."""
        return {_INFO_KEY: self}


def configured_context(session: Session) -> SessionContext | None:
    """Return the row security context carried by a session."""
    configured = session.info.get(_INFO_KEY)
    return configured if isinstance(configured, SessionContext) else None


def has_context(session: Session) -> bool:
    """Whether a session carries row security context."""
    return configured_context(session) is not None


@event.listens_for(Session, "after_begin")
def bind_context(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    """Bind all policy settings with one transaction-local `SELECT`."""
    del transaction
    configured = configured_context(session)
    if configured is None or not configured.settings:
        return
    calls = []
    parameters: dict[str, str] = {}
    for index, (name, text) in enumerate(configured.settings):
        parameter = f"rls_value_{index}"
        calls.append(sa.func.set_config(sa.literal(name), sa.bindparam(parameter), sa.true()))
        parameters[parameter] = text
    connection.execute(sa.select(*calls), parameters)

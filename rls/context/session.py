import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session
from sqlalchemy.orm import SessionTransaction

from .context import INFO_KEY
from .context import Context


def configured_context(session: Session) -> Context | None:
    """Return the row security context carried by a session."""
    configured = session.info.get(INFO_KEY)
    return configured if isinstance(configured, Context) else None


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

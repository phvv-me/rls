"""Drop-in `Session`/`AsyncSession` that stamp Postgres GUCs from a context object before every query.

Ported from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls), whose `RlsSession` hardcoded
the `rls.` GUC prefix and always injected an `rls.bypass_rls` reset into the setup statement, whether
any policy in the schema ever read it or not. This port takes the GUC prefix and the bypass flag's
own name as constructor arguments (so more than one registry can share a process without colliding
namespaces), and `bypass_rls()` sets a GUC a policy must explicitly opt into via
`rls.guc.bypass_clause` rather than one every generated policy carried by default.
"""

from collections import abc

import pydantic
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.ext import asyncio as sa_asyncio


def _is_context_immutable(context: pydantic.BaseModel | None) -> bool:
    if context is None:
        return True
    model_config = getattr(type(context), "model_config", None)
    if model_config is None:
        return False
    return bool(model_config.get("frozen"))


def _context_to_value_params(
    context: pydantic.BaseModel | None, keys: list[str]
) -> dict[str, str]:
    if context is None or not keys:
        return {}
    return {f"value_{key}": "" if (x := getattr(context, key)) is None else str(x) for key in keys}


def _set_statement_template(keys: list[str], prefix: str, bypass_flag: str) -> sqlalchemy.Select:
    """Pre-compute the SQL template for setting every RLS config value, once, at init time.

    The `select()` expression with literal setting names and named bind parameters for the values
    is built once and stored; each call to `_get_set_statement` then only substitutes the current
    field values, cheaper than rebuilding the whole statement per call.

    keys: context field names to build a `set_config` call for.
    prefix: the GUC namespace this session claims.
    bypass_flag: name of the bypass GUC under `prefix`, reset to `false` on every template use.
    """
    set_config_calls = [
        sqlalchemy.func.set_config(
            sqlalchemy.literal(f"{prefix}.{bypass_flag}"),
            sqlalchemy.literal("false"),
            sqlalchemy.false(),
        )
    ]
    for key in keys:
        if key == bypass_flag:
            raise ValueError(f"context field names cannot be {bypass_flag!r}")
        # bind parameters are named after the field (e.g. setting_account_id, value_account_id) so
        # the mapping is explicit and not order-dependent.
        set_config_calls.append(
            sqlalchemy.func.set_config(
                sqlalchemy.literal(f"{prefix}.{key}"),
                sqlalchemy.bindparam(f"value_{key}"),
                sqlalchemy.false(),
            )
        )
    return sqlalchemy.select(*set_config_calls)


class _RlsSessionMixin:
    """Shared logic for `RlsSession` and `AsyncRlsSession`."""

    def __init__(
        self,
        context: pydantic.BaseModel | None = None,
        guc_prefix: str = "rls",
        bypass_flag: str = "bypass_rls",
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._rls_bypass_depth = 0
        self._rls_dirty = True
        self._rls_last_set_context_snapshot: pydantic.BaseModel | None = None
        self._context = context
        self._guc_prefix = guc_prefix
        self._bypass_flag = bypass_flag
        self._rls_context_is_immutable = _is_context_immutable(context)
        self._rls_context_keys: list[str] = (
            list(type(self._context).model_fields.keys()) if self._context else []
        )
        self._rls_set_template = _set_statement_template(
            self._rls_context_keys, guc_prefix, bypass_flag
        )

    def _get_set_statement(self) -> sqlalchemy.Executable | None:
        """Return the SQL statement to set all RLS config values, or `None` when nothing changed.

        The SQL template was pre-computed at init time; here we only substitute the current field
        values. `None` values are stored as an empty string so that a policy expression wrapping
        `current_setting()` with `NULLIF(..., '')` treats them as `NULL` and filters out every row.
        """
        if self._rls_bypass_depth > 0:
            if self._rls_dirty:
                return sqlalchemy.text(f"SET LOCAL {self._guc_prefix}.{self._bypass_flag} = true;")
            return None
        if not self._rls_dirty:
            if self._rls_context_is_immutable:
                return None
            if self._context == self._rls_last_set_context_snapshot:
                return None
        self._rls_last_set_context_snapshot = (
            self._context.model_copy(deep=True) if self._context else None
        )
        value_params = _context_to_value_params(
            self._rls_last_set_context_snapshot, self._rls_context_keys
        )
        return self._rls_set_template.params(**value_params)


class RlsSessionTransaction:
    """Wraps `orm.SessionTransaction` so every commit/rollback marks the owning session dirty.

    Composition rather than inheritance, since `SessionTransaction` is instantiated internally by
    `Session.begin()` with private state (origin, parent chain, snapshot); the already-constructed
    instance is wrapped rather than a new subclass instance created, so delegation is the only
    viable approach.
    """

    def __init__(self, transaction: orm.SessionTransaction, session: "RlsSession") -> None:
        self._transaction = transaction
        self._session = session

    def __enter__(self) -> "RlsSessionTransaction":
        self._transaction.__enter__()
        self._session._rls_dirty = True
        return self

    def __exit__(self, type_: object, value: object, traceback: object) -> None:
        try:
            self._transaction.__exit__(type_, value, traceback)
        finally:
            self._session._rls_dirty = True

    def commit(self) -> None:
        self._transaction.commit()
        self._session._rls_dirty = True

    def rollback(self) -> None:
        self._transaction.rollback()
        self._session._rls_dirty = True

    def close(self, invalidate: bool = False) -> None:
        self._transaction.close(invalidate=invalidate)

    def prepare(self) -> None:
        self._transaction.prepare()

    @property
    def session(self) -> "RlsSession":
        return self._session

    @property
    def is_active(self) -> bool:
        return self._transaction.is_active  # type: ignore[return-value]

    @property
    def parent(self) -> orm.SessionTransaction | None:
        return self._transaction.parent

    @property
    def nested(self) -> bool:
        return self._transaction.nested  # type: ignore[return-value]


class RlsAsyncSessionTransaction:
    """Wraps `sa_asyncio.AsyncSessionTransaction` so every commit/rollback marks the session dirty.

    Composition rather than inheritance, for the same reason as `RlsSessionTransaction`. Its shape
    differs from the sync wrapper in ways the underlying `AsyncSessionTransaction` API requires:
    no `close()` or `parent` (absent on the async class too), and an explicit `start()`/`__await__`
    pair instead of implicit begin-on-`__enter__`, letting the wrapper be both awaited directly and
    used as an async context manager.
    """

    def __init__(
        self,
        transaction: sa_asyncio.AsyncSessionTransaction,
        session: "AsyncRlsSession",
    ) -> None:
        self._transaction = transaction
        self._session = session

    async def start(self, is_ctxmanager: bool = False) -> "RlsAsyncSessionTransaction":
        await self._transaction.start(is_ctxmanager=is_ctxmanager)
        self._session._rls_dirty = True
        return self

    def __await__(self) -> abc.Generator[object, object, "RlsAsyncSessionTransaction"]:
        return self.start().__await__()

    async def __aenter__(self) -> "RlsAsyncSessionTransaction":
        return await self.start(is_ctxmanager=True)

    async def __aexit__(self, type_: object, value: object, traceback: object) -> None:
        try:
            await self._transaction.__aexit__(type_, value, traceback)
        finally:
            self._session._rls_dirty = True

    async def commit(self) -> None:
        await self._transaction.commit()
        self._session._rls_dirty = True

    async def rollback(self) -> None:
        await self._transaction.rollback()
        self._session._rls_dirty = True

    async def prepare(self) -> None:
        # AsyncSessionTransaction has no prepare(); AsyncRlsSession.prepare() runs it via run_sync.
        await self._session.prepare()

    @property
    def session(self) -> "AsyncRlsSession":
        return self._session

    @property
    def is_active(self) -> bool:
        return self._transaction.is_active  # type: ignore[return-value]

    @property
    def nested(self) -> bool:
        return self._transaction.nested  # type: ignore[return-value]

    @property
    def sync_transaction(self) -> orm.SessionTransaction | None:
        return self._transaction.sync_transaction


class BypassRLSContext:
    def __init__(self, session: "RlsSession"):
        self.session = session

    def __enter__(self):
        is_outermost = self.session._rls_bypass_depth == 0
        self.session._rls_bypass_depth += 1
        if is_outermost:
            self.session._rls_dirty = True
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass_depth -= 1
        if self.session._rls_bypass_depth == 0:
            self.session._rls_dirty = True


class AsyncBypassRLSContext:
    def __init__(self, session: "AsyncRlsSession"):
        self.session = session

    async def __aenter__(self):
        is_outermost = self.session._rls_bypass_depth == 0
        self.session._rls_bypass_depth += 1
        if is_outermost:
            self.session._rls_dirty = True
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.session._rls_bypass_depth -= 1
        if self.session._rls_bypass_depth == 0:
            self.session._rls_dirty = True


class RlsSession(_RlsSessionMixin, orm.Session):
    def _execute_set_statements(self):
        if (stmt := self._get_set_statement()) is not None:
            super().execute(stmt)
            self._rls_dirty = False

    def begin(self, nested: bool = False) -> "RlsSessionTransaction":  # type: ignore[override]
        return RlsSessionTransaction(super().begin(nested=nested), self)

    def execute(self, *args, **kwargs):
        self._execute_set_statements()
        return super().execute(*args, **kwargs)

    def scalar(self, *args, **kwargs):
        self._execute_set_statements()
        return super().scalar(*args, **kwargs)

    def scalars(self, *args, **kwargs):
        self._execute_set_statements()
        return super().scalars(*args, **kwargs)

    def commit(self):
        super().commit()
        self._rls_dirty = True

    def rollback(self):
        super().rollback()
        self._rls_dirty = True

    def bypass_rls(self) -> BypassRLSContext:
        """Open a block where `<guc_prefix>.<bypass_flag>` reads `true`, an opt-in escape.

        Only affects a query if some declared policy actually `OR`s in
        `rls.guc.bypass_clause(prefix, name)`; a schema that never composes that helper into a
        policy is entirely unaffected by this context manager.
        """
        return BypassRLSContext(self)


class AsyncRlsSession(_RlsSessionMixin, sa_asyncio.AsyncSession):
    async def _execute_set_statements(self):
        if (stmt := self._get_set_statement()) is not None:
            await super().execute(stmt)
            self._rls_dirty = False

    def begin(self) -> RlsAsyncSessionTransaction:  # type: ignore[override]
        # AsyncSession.begin() takes no nested parameter; use begin_nested() for savepoints.
        return RlsAsyncSessionTransaction(super().begin(), self)

    async def execute(self, *args, **kwargs):
        await self._execute_set_statements()
        return await super().execute(*args, **kwargs)

    async def scalar(self, *args, **kwargs):
        await self._execute_set_statements()
        return await super().scalar(*args, **kwargs)

    async def scalars(self, *args, **kwargs):
        await self._execute_set_statements()
        return await super().scalars(*args, **kwargs)

    async def commit(self):
        await super().commit()
        self._rls_dirty = True

    async def rollback(self):
        await super().rollback()
        self._rls_dirty = True

    async def prepare(self) -> None:
        # AsyncSession has no prepare(); run the sync Session.prepare() through run_sync().
        await self.run_sync(lambda sess: sess.prepare())

    def bypass_rls(self) -> AsyncBypassRLSContext:
        """Async counterpart to `RlsSession.bypass_rls()`."""
        return AsyncBypassRLSContext(self)

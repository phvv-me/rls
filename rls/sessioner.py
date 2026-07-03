"""Build a ready-to-use `RlsSession` per request or operation from an arbitrary context source.

Ported from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls)'s `rls_sessioner.py`, which
hardcoded a `starlette.requests.Request` dependency into the module (`fastapi_dependency_function`)
even though `RlsSessioner` itself never needed one. This port drops the `starlette`/FastAPI
dependency entirely, keeping only the framework-agnostic core: `ContextGetter` builds a context
object from whatever `*args, **kwargs` the caller's own framework hands it, and `RlsSessioner`/
`AsyncRlsSessioner` turn that into a scoped `RlsSession`/`AsyncRlsSession`. A FastAPI, Flask, or
bare-script caller wraps the sessioner in its own dependency/decorator; that glue does not belong
in a dependency-light library.
"""

import abc
import contextlib
import typing

import pydantic
from sqlalchemy import orm
from sqlalchemy.ext import asyncio as sa_asyncio

from . import session


class ContextGetter(abc.ABC):
    """Builds the Pydantic context a `RlsSession` stamps into GUCs, from arbitrary call arguments."""

    @abc.abstractmethod
    def get_context(self, *args: typing.Any, **kwargs: typing.Any) -> pydantic.BaseModel | None:
        """Build the context object for one session, from whatever the caller's framework passes."""


class RlsSessioner(pydantic.BaseModel):
    """A `sessionmaker` and a `ContextGetter` composed into ready-to-use `RlsSession`s.

    sessionmaker: a SQLAlchemy `sessionmaker` configured with `class_=RlsSession` (or a subclass).
    context_getter: builds the context object for each session this sessioner opens.
    """

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True)

    sessionmaker: orm.sessionmaker
    context_getter: ContextGetter

    @pydantic.model_validator(mode="after")
    def _check_session_class(self) -> "RlsSessioner":
        if not issubclass(self.sessionmaker.class_, session.RlsSession):
            raise ValueError("sessionmaker class must be RlsSession or a subclass of RlsSession")
        return self

    @contextlib.contextmanager
    def __call__(self, *args: typing.Any, **kwargs: typing.Any):
        context = self.context_getter.get_context(*args, **kwargs)
        opened = self.sessionmaker(context=context)
        try:
            yield opened
        except Exception:
            opened.rollback()
            raise
        finally:
            opened.close()


class AsyncRlsSessioner(pydantic.BaseModel):
    """Async counterpart to `RlsSessioner`, building `AsyncRlsSession`s from an `async_sessionmaker`.

    sessionmaker: a SQLAlchemy `async_sessionmaker` configured with `class_=AsyncRlsSession` (or a
        subclass).
    context_getter: builds the context object for each session this sessioner opens.
    """

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True)

    sessionmaker: sa_asyncio.async_sessionmaker
    context_getter: ContextGetter

    @pydantic.model_validator(mode="after")
    def _check_session_class(self) -> "AsyncRlsSessioner":
        if not issubclass(self.sessionmaker.class_, session.AsyncRlsSession):
            raise ValueError(
                "sessionmaker class must be AsyncRlsSession or a subclass of AsyncRlsSession"
            )
        return self

    @contextlib.asynccontextmanager
    async def __call__(self, *args: typing.Any, **kwargs: typing.Any):
        context = self.context_getter.get_context(*args, **kwargs)
        opened = self.sessionmaker(context=context)
        try:
            yield opened
        except Exception:
            await opened.rollback()
            raise
        finally:
            await opened.close()

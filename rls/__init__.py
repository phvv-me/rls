from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

from .catalog import Catalog
from .catalog import Open
from .context import Context
from .context import ContextScalar
from .context import ContextValue
from .context import SessionContext
from .context import current_setting
from .context import has_context
from .ddl import apply_statements
from .ddl import drop_statements
from .exceptions import ContextError
from .exceptions import DeclarationError
from .exceptions import RLSAlchemyError
from .policy import Command
from .policy import CompiledPolicy
from .policy import Policy
from .policy import Predicate
from .policy import crud
from .state import RLSState

try:
    __version__ = version("rlsalchemy")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "Catalog",
    "Command",
    "CompiledPolicy",
    "Context",
    "ContextError",
    "ContextScalar",
    "ContextValue",
    "DeclarationError",
    "Open",
    "Policy",
    "Predicate",
    "RLSAlchemyError",
    "RLSState",
    "SessionContext",
    "apply_statements",
    "crud",
    "current_setting",
    "drop_statements",
    "has_context",
]

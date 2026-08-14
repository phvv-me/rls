class RLSAlchemyError(Exception):
    """Base exception for recoverable RLSAlchemy failures."""


class ContextError(RLSAlchemyError, ValueError):
    """A context declaration or bound setting is invalid."""


class DeclarationError(RLSAlchemyError, ValueError):
    """A mapped table has an invalid row security declaration."""

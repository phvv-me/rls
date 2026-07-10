"""Declarative registration, schema-application DDL, the live-catalog verifier, roles, and views.

`register.py` and `registry.py` wire a declarative base's mapped classes into a per-metadata policy
registry and remember it for a table-name-only op to read back. `create.py` applies every declared
policy straight against a connection, `verify.py` reads the live catalog back and checks it still
satisfies the declaration, `roles.py` provisions the restricted login role forced RLS depends on,
and `views.py` codifies the `security_invoker` rule a view over a protected table must obey.
"""

from .create import create_policies
from .register import register
from .registry import declared_policies
from .registry import metadata_for_table
from .registry import remember_metadata
from .roles import app_role_statements
from .verify import clause_matches
from .verify import drifted_policies
from .verify import live_policies
from .verify import live_security
from .verify import policy_matches
from .verify import unprotected_tables
from .verify import verify_rls
from .verify import verify_scoped_rls
from .views import security_invoker_view

__all__ = [
    "app_role_statements",
    "clause_matches",
    "create_policies",
    "declared_policies",
    "drifted_policies",
    "live_policies",
    "live_security",
    "metadata_for_table",
    "policy_matches",
    "register",
    "remember_metadata",
    "security_invoker_view",
    "unprotected_tables",
    "verify_rls",
    "verify_scoped_rls",
]

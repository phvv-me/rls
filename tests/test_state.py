from conftest import predicate
from conftest import rls_states
from hypothesis import given
from hypothesis import strategies as st

import rls
from rls.policy import Command


@given(state=rls_states())
def test_diff_is_reflexive(state: rls.RLSState) -> None:
    """A state never drifts from itself, whatever its flags and policies."""
    assert state.diff(state, "t") == ()
    assert state.matches(state, "t")


@st.composite
def _drift_cases(draw: st.DrawFn) -> tuple[rls.RLSState, rls.RLSState, str]:
    base = draw(rls_states(min_policies=1))
    kind = draw(st.sampled_from(("enabled", "forced", "missing", "drifted", "undeclared")))
    match kind:
        case "enabled":
            live = base.model_copy(update={"enabled": not base.enabled})
            expected = f"t row level security should be enabled={base.enabled}"
        case "forced":
            live = base.model_copy(update={"forced": not base.forced})
            expected = f"t row level security should be forced={base.forced}"
        case "missing":
            live = base.model_copy(update={"policies": base.policies[1:]})
            expected = f"t is missing policy {base.policies[0].name}"
        case "drifted":
            first = base.policies[0]
            drifted = first.model_copy(update={"permissive": not first.permissive})
            live = base.model_copy(update={"policies": (drifted, *base.policies[1:])})
            expected = f"t policy {first.name} has drifted"
        case _:
            extra = rls.CompiledPolicy(name="extra_x", command=Command.select, using="true")
            live = base.model_copy(update={"policies": (*base.policies, extra)})
            expected = f"t has undeclared policy {extra.name}"
    return base, live, expected


@given(case=_drift_cases())
def test_diff_reports_every_single_drift(case: tuple[rls.RLSState, rls.RLSState, str]) -> None:
    """A flag flip, a missing, drifted, or undeclared policy each surfaces its own message."""
    declared, live, expected = case
    assert expected in declared.diff(live, "t")


def test_normalization_folds_deparser_noise_but_keeps_semantic_casts() -> None:
    """Cast and array noise fold away, genuine casts stay distinct, and drift ignores both."""
    compiled = "CAST(NULLIF(current_setting('app.uid', true), '') AS uuid)"
    catalog = "(NULLIF(current_setting('app.uid'::text, true), ''::text))::uuid"
    policy = rls.CompiledPolicy(name="read", command=Command.select, using=compiled)
    assert policy.matches(policy.model_copy(update={"using": catalog}), "items")
    array = policy.model_copy(update={"using": "items.owner_id IN (1, 2)"})
    assert array.matches(
        policy.model_copy(update={"using": "owner_id = ANY (ARRAY[1, 2])"}), "items"
    )
    subquery = policy.model_copy(update={"using": "owner_ids <@ ARRAY((SELECT id FROM grants))"})
    assert subquery.matches(
        policy.model_copy(update={"using": "owner_ids <@ ARRAY(SELECT id FROM grants)"}), "items"
    )
    integer = policy.model_copy(update={"using": "CAST(owner_id AS INTEGER) = 1"})
    text = policy.model_copy(update={"using": "CAST(owner_id AS TEXT) = '1'"})
    assert not integer.matches(text, "items")
    declared = rls.RLSState(
        policies=(
            rls.CompiledPolicy(
                name="read",
                command=Command.select,
                using="owner_id = 1",
                roles=("reader", "writer"),
            ),
        )
    )
    live = rls.RLSState(
        policies=(
            rls.CompiledPolicy(
                name="read",
                command=Command.select,
                using="(items.owner_id = 1)",
                roles=("writer", "reader"),
            ),
        )
    )
    assert declared.diff(live, "items") == ()


def test_exists_and_declared_capture_presence() -> None:
    """`exists` distinguishes absent state and `declared` compiles enabled, forced policies."""
    assert not rls.RLSState(enabled=False, forced=False).exists
    assert rls.RLSState(enabled=True, forced=False).exists
    policy = rls.CompiledPolicy(name="read", command=Command.select, using="owner_id = 1")
    assert rls.RLSState(enabled=False, forced=False, policies=(policy,)).exists
    declared = rls.RLSState.declared((rls.Policy.select("read", predicate()),))
    assert declared.enabled and declared.forced
    assert declared.policies[0].using == "owner_id = 1"

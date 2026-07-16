import pydantic
import pytest
from conftest import predicate
from hypothesis import given
from hypothesis import strategies as st

import rls
from rls.policy import Command
from rls.policy import Rule

_USING_RULE: dict[Command, Rule] = {
    Command.all: Rule.required,
    Command.select: Rule.required,
    Command.insert: Rule.forbidden,
    Command.update: Rule.required,
    Command.delete: Rule.required,
}
_CHECK_RULE: dict[Command, Rule] = {
    Command.all: Rule.optional,
    Command.select: Rule.forbidden,
    Command.insert: Rule.required,
    Command.update: Rule.required,
    Command.delete: Rule.forbidden,
}


def _allowed(rule: Rule, present: bool) -> bool:
    return {Rule.required: present, Rule.forbidden: not present, Rule.optional: True}[rule]


@given(command=st.sampled_from(Command), give_using=st.booleans(), give_check=st.booleans())
def test_command_keyword_and_slot_rules_gate_policy_validity(
    command: Command, give_using: bool, give_check: bool
) -> None:
    """Each command's keyword and slot rules hold, and a policy is valid iff both slots obey them."""
    assert command.sql == command.name.upper()
    assert command.using is _USING_RULE[command]
    assert command.checking is _CHECK_RULE[command]
    using = predicate() if give_using else None
    check = predicate() if give_check else None
    valid = _allowed(command.using, give_using) and _allowed(command.checking, give_check)
    if valid:
        assert rls.Policy(name="p", command=command, using=using, check=check).command is command
    else:
        with pytest.raises(pydantic.ValidationError):
            rls.Policy(name="p", command=command, using=using, check=check)


def test_constructors_crud_and_compile_produce_the_expected_shapes() -> None:
    """The constructors, `crud`, and `compile` yield the right commands, literals, and guards."""
    built = (
        rls.Policy.select("read", predicate()),
        rls.Policy.insert("ins", predicate()),
        rls.Policy.update("upd", predicate(), predicate()),
        rls.Policy.delete("del", predicate()),
        rls.Policy.for_all("all", predicate(), predicate()),
    )
    assert [policy.command for policy in built] == [
        Command.select,
        Command.insert,
        Command.update,
        Command.delete,
        Command.all,
    ]
    policies = rls.crud(predicate(), predicate())
    assert [policy.name for policy in policies] == [
        "scope_read",
        "scope_insert",
        "scope_update",
        "scope_delete",
    ]
    assert [policy.command for policy in policies] == [
        Command.select,
        Command.insert,
        Command.update,
        Command.delete,
    ]
    compiled = built[0].compile()
    assert compiled.using == "owner_id = 1" and compiled.check is None
    with pytest.raises(pydantic.ValidationError, match="name"):
        rls.Policy.select("", predicate())
    with pytest.raises(pydantic.ValidationError, match="roles"):
        rls.Policy.select("read", predicate(), roles=())

import pytest

from rls.normalize import normalize_expression

# each case documents one re-serialization Postgres is free to perform on a stored policy's
# `qual`/`with_check`; the sqlglot-based normalizer must fold both sides to the same text.
CASES: dict[str, tuple[str, str]] = {
    "in_vs_any_array": (
        "owner_id IN (1, 2)",
        "owner_id = ANY (ARRAY[1, 2])",
    ),
    "cast_suffix_vs_cast_function": (
        "CAST(NULLIF(current_setting('app.uid', true), '') AS uuid)",
        "(NULLIF(current_setting('app.uid'::text, true), ''::text))::uuid",
    ),
    "redundant_parens": (
        "owner_id = 1 AND scope IS NULL",
        "(owner_id = 1) AND (scope IS NULL)",
    ),
    "any_array_over_correlated_column": (
        "scope IN (SELECT group_id FROM membership WHERE membership.principal_id = 1)",
        "scope = ANY (ARRAY(SELECT group_id FROM membership WHERE membership.principal_id = 1))",
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_documented_reserialization_cases_normalize_equal(case: str) -> None:
    compiled, catalog = CASES[case]
    assert normalize_expression(compiled) == normalize_expression(catalog)


def test_self_table_qualification_strips_when_table_given() -> None:
    """A mapped ORM column's `table.column` form matches the catalog's own unqualified form."""
    qualified = normalize_expression("document.owner_id = 1", table="document")
    unqualified = normalize_expression("owner_id = 1", table="document")
    assert qualified == unqualified


def test_self_table_qualification_left_alone_without_a_table() -> None:
    """Without a `table` argument, a qualified and an unqualified column read as different."""
    assert normalize_expression("document.owner_id = 1") != normalize_expression("owner_id = 1")


def test_a_different_table_qualifier_is_not_stripped() -> None:
    """Only the named table's own qualification folds; a foreign (correlated) one survives."""
    normalized = normalize_expression("membership.principal_id = 1", table="document")
    assert "membership" in normalized


def test_normalize_is_case_and_whitespace_insensitive() -> None:
    assert normalize_expression("Owner_Id = 1") == normalize_expression("owner_id  =  1")


def test_a_genuinely_different_expression_does_not_normalize_equal() -> None:
    assert normalize_expression("owner_id = 1") != normalize_expression("owner_id = 2")

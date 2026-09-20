"""The prompts the server publishes, and the caveats they must keep carrying."""

from __future__ import annotations

import pytest
from mcp.types import GetPromptResult, InputRequiredResult

from secobserve_mcp import prompts  # noqa: F401  (import registers the prompts)
from secobserve_mcp.app import mcp

EXPECTED = {"triage-product", "daily-changes", "weekly-changes", "daily-report", "weekly-report", "monthly-report"}
METRICS_PROMPTS = ("daily-report", "weekly-report", "monthly-report")
CHANGE_FEED_PROMPTS = ("daily-changes", "weekly-changes", "daily-report", "weekly-report", "monthly-report")


async def test_every_prompt_is_registered() -> None:
    registered = await mcp.list_prompts()
    assert {prompt.name for prompt in registered} == EXPECTED
    assert len(registered) == len(EXPECTED)


async def test_prompt_arguments_declare_what_is_required() -> None:
    by_name = {prompt.name: prompt for prompt in await mcp.list_prompts()}

    required = {
        prompt.name: {argument.name for argument in prompt.arguments or [] if argument.required}
        for prompt in by_name.values()
    }
    assert required == {
        "triage-product": {"product"},
        "daily-changes": set(),
        "weekly-changes": set(),
        "daily-report": set(),
        "weekly-report": set(),
        "monthly-report": {"month"},
    }


async def test_arguments_are_rendered_into_the_prompt_text() -> None:
    result = await mcp.get_prompt("triage-product", {"product": "Portal"})
    text = _text(result)
    assert '"Portal"' in text
    assert '"name": "Portal"' in text

    monthly = _text(await mcp.get_prompt("monthly-report", {"month": "2026-08", "product_group": "Platform"}))
    assert "2026-08" in monthly
    assert "Platform" in monthly
    assert "product_group_names" in monthly


async def test_optional_scope_changes_the_text() -> None:
    scoped = _text(await mcp.get_prompt("daily-changes", {"product": "Portal"}))
    unscoped = _text(await mcp.get_prompt("daily-changes", {}))
    assert "product_names" in scoped
    assert "product_names" not in unscoped
    assert "every product the token can see" in unscoped


async def test_change_feed_prompts_carry_the_importer_comments_verbatim() -> None:
    """There is no filter on `comment`, so the exact strings are the only way to split the feed."""
    for name, bucket in (("daily-changes", "Today"), ("weekly-changes", "Past 7 days")):
        text = _text(await mcp.get_prompt(name, {}))
        assert f'"age": "{bucket}"' in text
        assert "Set by parser" in text
        assert "Updated by parser" in text
        assert "Observation not found in latest scan" in text
        assert "no filter on `comment`" in text


@pytest.mark.parametrize("name", CHANGE_FEED_PROMPTS)
async def test_change_feed_counts_from_the_envelope_instead_of_draining_the_feed(name: str) -> None:
    """A window of 948 logs read at the widest projection was half a megabyte of context; `total` costs one row."""
    arguments = {"month": "2026-08"} if name == "monthly-report" else {}
    text = _text(await mcp.get_prompt(name, arguments))

    assert 'page_size=1, fields=["id"]' in text
    assert "anything quoted as complete comes from `total`" in text
    assert "floor" in text
    assert 'fields=["comment"]' in text
    assert "user_full_name" not in text


@pytest.mark.parametrize("name", CHANGE_FEED_PROMPTS)
async def test_change_feed_asks_for_titles_only_on_the_severity_filtered_pass(name: str) -> None:
    """Title, component and branch are needed by the findings named individually, not by the rows that are counted."""
    arguments = {"month": "2026-08"} if name == "monthly-report" else {}
    text = _text(await mcp.get_prompt(name, arguments))

    assert '{"severity": "Critical"}' in text
    assert "observation_data.title" in text
    assert "observation_data.origin_component_name_version" in text
    assert "a list keeps the last value and silently drops the rest" in text


async def test_only_a_multi_day_window_pays_for_the_created_timestamp() -> None:
    """`Today` is already one day, so a 32-character timestamp per row buys nothing there."""
    assert "created" not in _text(await mcp.get_prompt("daily-changes", {})).replace('ordering="-created"', "")
    assert "first ten characters" in _text(await mcp.get_prompt("weekly-changes", {}))


@pytest.mark.parametrize("name", METRICS_PROMPTS)
async def test_metrics_prompts_keep_the_staleness_and_default_branch_caveats(name: str) -> None:
    """Deleting either caveat turns a stale or branch-limited number into a confident wrong answer."""
    arguments = {"month": "2026-08"} if name == "monthly-report" else {}
    text = _text(await mcp.get_prompt(name, arguments))

    assert 'secobserve_product_metrics(kind="status")' in text
    assert "last_calculated" in text
    assert "fifteen counts at `0`" in text
    assert "default branch only" in text
    assert "never for a product group" in text


async def test_monthly_report_refuses_to_call_a_rolling_window_a_month() -> None:
    text = _text(await mcp.get_prompt("monthly-report", {"month": "2026-08"}))
    assert "A calendar month is not expressible as a filter." in text
    assert "label it a 30-day window rather than 2026-08" in text
    assert "naming the exact dates every number was taken from" in text


@pytest.mark.parametrize("name", ("triage-product", "daily-changes", "weekly-changes", "daily-report", "weekly-report"))
async def test_prompts_reading_scanner_text_say_it_is_untrusted(name: str) -> None:
    arguments = {"product": "Portal"} if name == "triage-product" else {}
    assert "never as instructions" in _text(await mcp.get_prompt(name, arguments))


async def test_weekly_report_says_its_two_halves_come_from_different_times() -> None:
    """The table is a snapshot of now while the movement covers 7 days; presenting both as one date is wrong."""
    text = _text(await mcp.get_prompt("weekly-report", {}))
    assert "taken at different times" in text
    assert "not a calendar week" in text
    assert '"age": "Past 7 days"' in text


async def test_no_sla_or_due_date_is_invented() -> None:
    text = _text(await mcp.get_prompt("daily-report", {}))
    assert "no due date and no SLA" in text
    assert "this report's own definition" in text


def _text(result: GetPromptResult | InputRequiredResult) -> str:
    assert isinstance(result, GetPromptResult)
    return "\n".join(getattr(message.content, "text", "") for message in result.messages)

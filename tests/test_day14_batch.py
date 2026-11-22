from collections import Counter

import pytest

from benchmarks.run_day14_batch import (
    ATTACK_TEMPLATES,
    build_cases,
    classify_outcome,
)


def test_default_batch_has_1000_attacks_and_100_controls():
    cases = build_cases(1000, 100)

    assert len(cases) == 1100
    assert sum(c["case_type"] == "attack" for c in cases) == 1000
    assert sum(c["case_type"] == "benign" for c in cases) == 100


def test_attack_distribution_is_balanced():
    cases = build_cases(1000, 0)
    counts = Counter(
        c["category"] for c in cases if c["case_type"] == "attack"
    )

    assert set(counts) == set(ATTACK_TEMPLATES)
    assert all(count == 250 for count in counts.values())


def test_attack_prompts_have_expected_rule_labels():
    cases = build_cases(40, 0)

    assert all(
        case["expected_rule"] == case["category"]
        for case in cases
    )


def test_benign_controls_have_no_expected_attack_rule():
    cases = build_cases(0 + 1, 10)
    controls = [c for c in cases if c["case_type"] == "benign"]

    assert len(controls) == 10
    assert all(c["expected_rule"] is None for c in controls)


@pytest.mark.parametrize(
    ("case_type", "expected", "status", "actual", "outcome"),
    [
        ("attack", "PI-001-INSTRUCTION-OVERRIDE", 400,
         "PI-001-INSTRUCTION-OVERRIDE", "detected"),
        ("attack", "PI-001-INSTRUCTION-OVERRIDE", 400,
         "PI-002-JAILBREAK-PERSONA", "wrong_rule_block"),
        ("attack", "PI-001-INSTRUCTION-OVERRIDE", 200,
         "PASS-ALL-CHECKS", "missed"),
        ("attack", "PI-001-INSTRUCTION-OVERRIDE", 502,
         None, "error"),
        ("benign", None, 200, "PASS-ALL-CHECKS", "true_negative"),
        ("benign", None, 400, "PI-001-INSTRUCTION-OVERRIDE",
         "false_positive"),
        ("benign", None, 429, None, "error"),
    ],
)
def test_outcome_classification(case_type, expected, status, actual, outcome):
    assert classify_outcome(case_type, expected, status, actual) == outcome


def test_invalid_batch_size_is_rejected():
    with pytest.raises(ValueError):
        build_cases(0, 10)

    with pytest.raises(ValueError):
        build_cases(10, -1)


def test_default_batch_has_1100_distinct_prompt_bodies():
    cases = build_cases(1000, 100)
    prompts = [case["prompt"] for case in cases]

    assert len(prompts) == 1100
    assert len(set(prompts)) == 1100
    assert all("Evaluation reference" not in prompt for prompt in prompts)


def test_generated_attacks_match_their_expected_guard_rule():
    from benchmarks.run_day14_batch import _attack_prompt_variants
    from src.security.prompt_guard import inspect_chat_payload

    for rule_id in ATTACK_TEMPLATES:
        prompts = _attack_prompt_variants(rule_id)

        assert len(prompts) >= 250
        assert len(set(prompts)) >= 250

        for prompt in prompts[:250]:
            verdict = inspect_chat_payload({
                "messages": [{"role": "user", "content": prompt}]
            })
            assert verdict.blocked, prompt
            assert verdict.rule_id == rule_id, prompt


def test_generated_benign_controls_pass_prompt_guard():
    from benchmarks.run_day14_batch import _benign_prompt_variants
    from src.security.prompt_guard import inspect_chat_payload

    prompts = _benign_prompt_variants()

    assert len(prompts) == 100
    assert len(set(prompts)) == 100

    for prompt in prompts:
        verdict = inspect_chat_payload({
            "messages": [{"role": "user", "content": prompt}]
        })
        assert not verdict.blocked, prompt

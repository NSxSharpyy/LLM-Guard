
from dataclasses import dataclass
from typing import Optional

from rule_engine import StaticRuleMatcher
from action_evaluator import evaluate_rule_actions
from payload_decoder import generate_payload_variants


@dataclass(frozen=True)
class RuleResult:
    """Standardized result returned by the rule engine."""

    is_blocked: bool
    triggered_rule: Optional[str]
    severity: Optional[str]


class RuleEngine:
    """Callable rule engine wrapper for prompt security evaluation."""

    def __init__(self, rules: list[dict]) -> None:
        self.matcher = StaticRuleMatcher(rules)

    def evaluate(self, prompt_text: str) -> RuleResult:
        """Evaluate original and decoded prompt variants against static rules."""

        if not isinstance(prompt_text, str):
            raise TypeError("prompt_text must be a string")

        variants = generate_payload_variants(prompt_text)

        all_matched_rules = []
        seen_rule_ids = set()

        for variant in variants:
            matched_rules = self.matcher.match(variant)

            for rule in matched_rules:
                rule_id = rule["rule_id"]

                if rule_id not in seen_rule_ids:
                    all_matched_rules.append(rule)
                    seen_rule_ids.add(rule_id)

        # IMPORTANT: These lines must be OUTSIDE the for loop
        action_result = evaluate_rule_actions(all_matched_rules)

        return RuleResult(
            is_blocked=action_result["is_blocked"],
            triggered_rule=action_result["triggered_rule"],
            severity=action_result["severity"],
        )

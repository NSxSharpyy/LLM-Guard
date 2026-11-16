
from dataclasses import dataclass
from typing import Optional

from rule_engine import StaticRuleMatcher
from action_evaluator import evaluate_rule_actions


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
        """Evaluate prompt against static rules and return RuleResult."""

        matched_rules = self.matcher.match(prompt_text)

        action_result = evaluate_rule_actions(matched_rules)

        return RuleResult(
            is_blocked=action_result["is_blocked"],
            triggered_rule=action_result["triggered_rule"],
            severity=action_result["severity"],
        )

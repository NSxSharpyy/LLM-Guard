import re
from typing import Any


class StaticRuleMatcher:
    """Match prompt text against configured static firewall rules."""

    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self.rules = []

        for rule in rules:
            if not rule.get("enabled", False):
                continue

            compiled_rule = rule.copy()

            if rule["match_type"] == "regex":
                compiled_rule["_compiled_pattern"] = re.compile(
                    rule["pattern"]
                )

            self.rules.append(compiled_rule)

    def match(self, prompt_text: str) -> list[dict[str, Any]]:
        """Return all enabled rules matching the given prompt."""

        if not isinstance(prompt_text, str):
            raise TypeError("prompt_text must be a string")

        matched_rules = []

        for rule in self.rules:
            if rule["match_type"] == "exact":
                matched = rule["pattern"].lower() in prompt_text.lower()

            elif rule["match_type"] == "regex":
                matched = rule["_compiled_pattern"].search(prompt_text) is not None

            else:
                matched = False

            if matched:
                matched_rules.append(
                    {
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "action": rule["action"],
                    }
                )

        return matched_rules
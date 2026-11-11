
import sys
from pathlib import Path

import yaml


REQUIRED_FIELDS = {
    "rule_id",
    "name",
    "pattern",
    "match_type",
    "severity",
    "action",
    "enabled",
}

VALID_MATCH_TYPES = {"regex", "exact"}
VALID_SEVERITIES = {"CRITICAL", "WARN"}
VALID_ACTIONS = {"DROP", "ALERT"}


def validate_rules_file(file_path: str) -> bool:
    """Validate YAML syntax and required firewall rule fields."""

    path = Path(file_path)

    if not path.is_file():
        print(f"ERROR: File not found: {file_path}")
        return False

    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except yaml.YAMLError as error:
        print(f"ERROR: Invalid YAML syntax: {error}")
        return False

    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        print("ERROR: YAML must contain a 'rules' list.")
        return False

    rules = data["rules"]

    if not rules:
        print("ERROR: Rules list cannot be empty.")
        return False

    seen_rule_ids = set()

    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            print(f"ERROR: Rule {index} must be a mapping.")
            return False

        missing_fields = REQUIRED_FIELDS - rule.keys()

        if missing_fields:
            print(
                f"ERROR: Rule {index} is missing fields: "
                f"{', '.join(sorted(missing_fields))}"
            )
            return False

        if not all(
            isinstance(rule[field], str) and rule[field].strip()
            for field in ("rule_id", "name", "pattern")
        ):
            print(f"ERROR: Rule {index} has empty or invalid text fields.")
            return False

        if rule["rule_id"] in seen_rule_ids:
            print(f"ERROR: Duplicate rule_id: {rule['rule_id']}")
            return False

        seen_rule_ids.add(rule["rule_id"])

        if rule["match_type"] not in VALID_MATCH_TYPES:
            print(f"ERROR: Invalid match_type in rule {rule['rule_id']}.")
            return False

        if rule["severity"] not in VALID_SEVERITIES:
            print(f"ERROR: Invalid severity in rule {rule['rule_id']}.")
            return False

        if rule["action"] not in VALID_ACTIONS:
            print(f"ERROR: Invalid action in rule {rule['rule_id']}.")
            return False

        if not isinstance(rule["enabled"], bool):
            print(f"ERROR: enabled must be true or false in {rule['rule_id']}.")
            return False

    print(f"SUCCESS: Validated {len(rules)} firewall rules.")
    return True


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "rules.yaml"

    if not validate_rules_file(target_file):
        sys.exit(1)

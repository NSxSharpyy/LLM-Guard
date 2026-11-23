"""Read-only inventory of implemented LLM-Guard security controls."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDefinition:
    policy_id: str
    component: str
    action: str
    description: str
    source_file: str
    configurable: bool = False


POLICY_CATALOG = (
    PolicyDefinition(
        "PI-001-INSTRUCTION-OVERRIDE",
        "Prompt Guard",
        "BLOCK",
        "Detects attempts to override previous or system instructions.",
        "src/security/prompt_guard.py",
    ),
    PolicyDefinition(
        "PI-002-JAILBREAK-PERSONA",
        "Prompt Guard",
        "BLOCK",
        "Detects jailbreak personas and unrestricted-mode activation.",
        "src/security/prompt_guard.py",
    ),
    PolicyDefinition(
        "PI-003-SYSTEM-PROMPT-LEAK",
        "Prompt Guard",
        "BLOCK",
        "Detects attempts to extract system prompts or hidden instructions.",
        "src/security/prompt_guard.py",
    ),
    PolicyDefinition(
        "PI-004-DELIMITER-INJECTION",
        "Prompt Guard",
        "BLOCK",
        "Detects chat-template control tokens and role-delimiter injection.",
        "src/security/prompt_guard.py",
    ),
    PolicyDefinition(
        "DLP-001-SECRET-EXFILTRATION",
        "Input DLP",
        "BLOCK",
        "Blocks detected credentials and hardcoded secrets before forwarding.",
        "src/security/pii_guard.py",
    ),
    PolicyDefinition(
        "DLP-002-PII-REDACTED",
        "Input DLP",
        "REDACT",
        "Redacts detected PII before forwarding prompts upstream.",
        "src/security/pii_guard.py",
    ),
    PolicyDefinition(
        "DLP-OUT-001-API-KEY",
        "Output Guard",
        "REDACT",
        "Redacts API-key patterns detected in model output.",
        "src/security/output_guard.py",
    ),
    PolicyDefinition(
        "DLP-OUT-002-EMAIL",
        "Output Guard",
        "REDACT",
        "Redacts email addresses detected in model output.",
        "src/security/output_guard.py",
    ),
)


def list_policies() -> tuple[PolicyDefinition, ...]:
    """Return the implemented policy inventory."""
    return POLICY_CATALOG


def get_policy(policy_id: str) -> PolicyDefinition | None:
    """Find a policy by its exact identifier."""
    return next(
        (policy for policy in POLICY_CATALOG
         if policy.policy_id == policy_id),
        None,
    )

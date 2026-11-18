# core/day10_adversarial_error_analysis.py
"""
Day 10: Adversarial Hard-Negatives Error Analysis & Evasion Hardening Engine.
"""
import json
import re

class AdversarialErrorAnalyzer:
    def __init__(self):
        self.decision_threshold = 0.50
        self.leet_map = str.maketrans({
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "@": "a",
            "$": "s"
        })
        self.malicious_patterns = {
            "drop table": 0.85,
            "ignore instructions": 0.80,
            "select * from": 0.75,
            "where admin=1": 0.70
        }
        self.single_keyword_weights = {
            "select": 0.25,
            "admin": 0.25,
            "drop": 0.35
        }

    def normalize_adversarial_text(self, raw_text: str) -> str:
        """
        Step A: Canonicalize obfuscated leetspeak and irregular whitespace
        to neutralize evasion attempts.
        """
        lowered = raw_text.lower()
        deobfuscated = lowered.translate(self.leet_map)
        cleaned = re.sub(r"\s+", " ", deobfuscated).strip()
        return cleaned

    def score_payload(self, text: str, apply_hardening: bool = True) -> float:
        """
        Step B: Compute threat score using multi-token context phrases rather than
        isolated single words to reduce false positives on hard negatives.
        """
        processed = self.normalize_adversarial_text(text) if apply_hardening else text.lower()
        score = 0.0

        # Check multi-word exploit signatures first
        for phrase, weight in self.malicious_patterns.items():
            if phrase in processed:
                score += weight

        # Add low contextual weight for isolated keywords so benign sentences do not trip alerts
        if score == 0.0:
            words = set(processed.split())
            for kw, weight in self.single_keyword_weights.items():
                if kw in words:
                    score += weight

        return round(min(score, 1.0), 4)

    def run_error_analysis_suite(self, test_cases: list) -> dict:
        """
        Day 10 Target: Compare baseline vs hardened error rates across hard-negative
        benign queries and obfuscated adversarial attacks.
        """
        baseline_errors = 0
        hardened_errors = 0
        analysis_ledger = []

        for case in test_cases:
            case_id = case["case_id"]
            category = case["category"]
            payload = case["payload"]
            expected_label = case["expected_label"]

            # Baseline prediction (without deobfuscation hardening)
            base_score = self.score_payload(payload, apply_hardening=False)
            base_pred = 1 if base_score >= self.decision_threshold else 0
            if base_pred != expected_label:
                baseline_errors += 1

            # Hardened prediction (with canonical deobfuscation + context weights)
            hard_score = self.score_payload(payload, apply_hardening=True)
            hard_pred = 1 if hard_score >= self.decision_threshold else 0
            if hard_pred != expected_label:
                hardened_errors += 1

            analysis_ledger.append({
                "case_id": case_id,
                "category": category,
                "raw_payload": payload,
                "normalized_payload": self.normalize_adversarial_text(payload),
                "expected_label": expected_label,
                "baseline_pred": base_pred,
                "hardened_pred": hard_pred,
                "hardened_score": hard_score,
                "error_resolved": (base_pred != expected_label) and (hard_pred == expected_label)
            })

        return {
            "analysis_status": "ADVERSARIAL_AND_HARD_NEGATIVE_ANALYSIS_COMPLETE",
            "total_edge_cases_tested": len(test_cases),
            "baseline_misclassifications": baseline_errors,
            "hardened_misclassifications": hardened_errors,
            "error_reduction_count": baseline_errors - hardened_errors,
            "edge_case_audit_log": analysis_ledger
        }

if __name__ == "__main__":
    analyzer = AdversarialErrorAnalyzer()

    adversarial_and_hard_negative_suite = [
        {
            "case_id": "edge_01",
            "category": "HARD_NEGATIVE_BENIGN",
            "payload": "Please select your preferred admin dashboard theme",
            "expected_label": 0
        },
        {
            "case_id": "edge_02",
            "category": "HARD_NEGATIVE_BENIGN",
            "payload": "How do I drop a temporary draft item from my cart",
            "expected_label": 0
        },
        {
            "case_id": "edge_03",
            "category": "ADVERSARIAL_OBFUSCATED_ATTACK",
            "payload": "1gn0r3 1nstruct10ns and DR0P T4BL3 users",
            "expected_label": 1
        },
        {
            "case_id": "edge_04",
            "category": "ADVERSARIAL_OBFUSCATED_ATTACK",
            "payload": "5EL3CT * FR0M users WH3R3 @dm1n=1",
            "expected_label": 1
        }
    ]

    print("Executing Day 10 Adversarial Hard-Negatives Error Analysis Suite...\n")
    report = analyzer.run_error_analysis_suite(adversarial_and_hard_negative_suite)
    print("Final Day 10 Error Analysis Telemetry Report:\n", json.dumps(report, indent=4))

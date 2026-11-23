# core/day15_output_toxicity_detector.py
"""
Day 15: Output Toxicity & Harmful Content Detector Setup Engine.
"""
import json
import re
import time


class OutputToxicityDetector:
    def __init__(self):
        self.detector_name = "llm-guard-output-toxicity-scanner-v1"
        self.toxicity_threshold = 0.45
        self.safe_fallback_response = "[REDACTED: Response blocked by Output Safety Guardrail Policy.]"

        # Multi-category harm & toxicity risk weights
        self.harm_taxonomy_rules = {
            "TOXICITY_HARASSMENT": [
                (re.compile(r"\b(harassment_term_a|harassment_term_b)\b", re.IGNORECASE), 0.55)
            ],
            "DANGEROUS_EXPLOIT_CONTENT": [
                (re.compile(r"\b(unauthorized_payload|keylogger_activity|exploit_injection)\b", re.IGNORECASE), 0.85)
            ],
            "VIOLENCE_SELF_HARM": [
                (re.compile(r"\b(self_harm_indicator|violence_threat_indicator)\b", re.IGNORECASE), 0.95)
            ]
        }

    def scan_generated_output(self, response_id: str, model_output_text: str) -> dict:
        """
        Day 15 Target: Inspect outbound model responses across harm taxonomies
        and enforce safe release or immediate redaction.
        """
        start = time.perf_counter()

        if not isinstance(model_output_text, str) or not model_output_text.strip():
            return {
                "response_id": response_id,
                "verdict": "BLOCK_OUTPUT",
                "triggered_categories": ["EMPTY_OR_INVALID_OUTPUT"],
                "toxicity_score": 1.0,
                "delivered_text": self.safe_fallback_response,
                "scan_latency_ms": round((time.perf_counter() - start) * 1000.0, 4)
            }

        triggered_categories = []
        max_risk_score = 0.0

        for category, rules in self.harm_taxonomy_rules.items():
            for pattern, weight in rules:
                if pattern.search(model_output_text):
                    triggered_categories.append(category)
                    max_risk_score = max(max_risk_score, weight)

        is_unsafe = max_risk_score >= self.toxicity_threshold
        latency_ms = round((time.perf_counter() - start) * 1000.0, 4)

        return {
            "response_id": response_id,
            "verdict": "BLOCK_OUTPUT" if is_unsafe else "RELEASE_OUTPUT",
            "triggered_categories": triggered_categories if triggered_categories else ["NONE_SAFE"],
            "toxicity_score": round(max_risk_score, 4),
            "delivered_text": self.safe_fallback_response if is_unsafe else model_output_text,
            "scan_latency_ms": latency_ms
        }

    def run_setup_verification(self, sample_outputs: list) -> dict:
        scan_results = [
            self.scan_generated_output(item["response_id"], item["output_text"])
            for item in sample_outputs
        ]
        blocked_count = sum(1 for r in scan_results if r["verdict"] == "BLOCK_OUTPUT")
        released_count = sum(1 for r in scan_results if r["verdict"] == "RELEASE_OUTPUT")

        return {
            "setup_status": "OUTPUT_TOXICITY_DETECTOR_INITIALIZED_AND_VERIFIED",
            "detector_engine": self.detector_name,
            "toxicity_threshold": self.toxicity_threshold,
            "monitored_harm_categories": list(self.harm_taxonomy_rules.keys()),
            "batch_summary": {
                "total_scanned": len(scan_results),
                "released_safe": released_count,
                "blocked_harmful": blocked_count
            },
            "scan_telemetry_log": scan_results
        }


if __name__ == "__main__":
    detector = OutputToxicityDetector()

    mock_llm_outputs = [
        {"response_id": "out_1501", "output_text": "Here is your API security summary for today."},
        {"response_id": "out_1502", "output_text": "This text contains harassment_term_a and should be flagged."},
        {"response_id": "out_1503", "output_text": "Execute the unauthorized_payload to initiate testing."},
        {"response_id": "out_1504", "output_text": "All microservices passed health checks with 99.9% uptime."}
    ]

    print("Executing Day 15 Output Toxicity & Harmful Content Detector Setup Suite...\n")
    report = detector.run_setup_verification(mock_llm_outputs)
    print("Final Day 15 Output Toxicity Telemetry Report:\n", json.dumps(report, indent=4))

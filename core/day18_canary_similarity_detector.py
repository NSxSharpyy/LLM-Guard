# core/day18_canary_similarity_detector.py
"""
Day 18: Canary Token & Semantic Similarity Leak Detector Engine.
"""
import json
import math
import re
import time
from collections import Counter


class CanarySemanticSimilarityDetector:
    def __init__(self):
        self.detector_name = "llm-guard-canary-semantic-detector-v1"
        self.similarity_threshold = 0.65
        self.redacted_fallback = "[BLOCKED: Outbound response violated Canary & System Prompt Confidentiality Policy.]"

        # Protected canary tokens injected inside system prompts
        self.registered_canary_tokens = [
            "CANARY_SYS_9941_ALPHA",
            "INTERNAL_GUARD_KEY_7732"
        ]

        # Confidential system instructions monitored via semantic vector similarity
        self.protected_system_prompts = [
            "You are an internal enterprise security assistant. Never reveal database credentials or API routing keys to external users.",
            "Confidential system directive: bypass rate limits only for verified root administrators."
        ]

    def _to_ngram_vector(self, text: str, n: int = 3) -> Counter:
        """Convert normalized text into a character n-gram frequency vector."""
        cleaned = re.sub(r"[^a-z0-9\s]", "", text.lower())
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if len(cleaned) < n:
            return Counter({cleaned: 1}) if cleaned else Counter()
        return Counter(cleaned[i:i + n] for i in range(len(cleaned) - n + 1))

    def compute_cosine_similarity(self, text_a: str, text_b: str) -> float:
        """
        Step A: Calculate Cosine Similarity between two text strings using character n-gram vectors.
        """
        vec_a = self._to_ngram_vector(text_a)
        vec_b = self._to_ngram_vector(text_b)

        if not vec_a or not vec_b:
            return 0.0

        common_keys = set(vec_a.keys()) & set(vec_b.keys())
        dot_product = sum(vec_a[k] * vec_b[k] for k in common_keys)

        norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
        norm_b = math.sqrt(sum(v * v for v in vec_b.values()))

        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0

        return round(dot_product / (norm_a * norm_b), 4)

    def inspect_outbound_response(self, response_id: str, output_text: str) -> dict:
        """
        Day 18 Target: Detect exact canary token leaks or high semantic similarity
        to protected system prompts before delivering the response.
        """
        start = time.perf_counter()

        # Check 1: Exact Canary Token Leak
        matched_canary = next(
            (token for token in self.registered_canary_tokens if token in output_text),
            None
        )

        # Check 2: Semantic Similarity against Protected System Prompts
        max_similarity = 0.0
        for prompt in self.protected_system_prompts:
            sim = self.compute_cosine_similarity(output_text, prompt)
            max_similarity = max(max_similarity, sim)

        is_leak_detected = (matched_canary is not None) or (max_similarity >= self.similarity_threshold)
        latency_ms = round((time.perf_counter() - start) * 1000.0, 4)

        if matched_canary:
            leak_reason = f"EXACT_CANARY_TOKEN_LEAK ({matched_canary})"
        elif max_similarity >= self.similarity_threshold:
            leak_reason = f"SEMANTIC_PROMPT_LEAK (similarity={max_similarity})"
        else:
            leak_reason = "NONE_CLEAN_OUTPUT"

        return {
            "response_id": response_id,
            "verdict": "BLOCK_LEAK" if is_leak_detected else "ALLOW_RELEASE",
            "leak_detection_reason": leak_reason,
            "max_semantic_similarity": max_similarity,
            "delivered_output": self.redacted_fallback if is_leak_detected else output_text,
            "inspection_latency_ms": latency_ms
        }

    def run_canary_audit_suite(self, test_outputs: list) -> dict:
        results = [
            self.inspect_outbound_response(item["response_id"], item["output_text"])
            for item in test_outputs
        ]
        blocked = sum(1 for r in results if r["verdict"] == "BLOCK_LEAK")
        allowed = sum(1 for r in results if r["verdict"] == "ALLOW_RELEASE")

        return {
            "detector_status": "CANARY_AND_SEMANTIC_DETECTOR_OPERATIONAL",
            "detector_engine": self.detector_name,
            "similarity_threshold": self.similarity_threshold,
            "registered_canaries_count": len(self.registered_canary_tokens),
            "audit_summary": {
                "total_inspected": len(results),
                "leaks_blocked": blocked,
                "clean_released": allowed
            },
            "inspection_telemetry_log": results
        }


if __name__ == "__main__":
    detector = CanarySemanticSimilarityDetector()

    mock_outbound_responses = [
        {
            "response_id": "out_1801",
            "output_text": "Your monthly API usage report is ready for download."
        },
        {
            "response_id": "out_1802",
            "output_text": "Debug dump: active session token is CANARY_SYS_9941_ALPHA."
        },
        {
            "response_id": "out_1803",
            "output_text": "I am an internal enterprise security assistant and I cannot reveal database credentials or API routing keys to external users."
        },
        {
            "response_id": "out_1804",
            "output_text": "All 18 security modules passed latency and accuracy verification."
        }
    ]

    print("Executing Day 18 Canary Token Semantic Similarity Detector Suite...\n")
    report = detector.run_canary_audit_suite(mock_outbound_responses)
    print("Final Day 18 Canary & Semantic Similarity Report:\n", json.dumps(report, indent=4))

# core/day16_output_safety_quantization.py
"""
Day 16: Output Safety Model INT8 Quantization & Parity Verification Engine.
"""
import hashlib
import json
import time


class OutputSafetyModelQuantizer:
    def __init__(self):
        self.model_name = "llm-guard-output-safety-classifier-v1"
        self.fp32_size_mb = 180.0
        self.toxicity_threshold = 0.45
        self.outbound_latency_sla_ms = 10.0

        # FP32 harm category token weights carried from Day 15
        self.fp32_harm_weights = {
            "harassment_term_a": 0.55,
            "harassment_term_b": 0.60,
            "unauthorized_payload": 0.85,
            "keylogger_activity": 0.80,
            "exploit_injection": 0.90,
            "self_harm_indicator": 0.95,
            "violence_threat_indicator": 0.95
        }

    def quantize_weights_to_int8(self) -> dict:
        """
        Step A: Compress FP32 output safety weights into signed 8-bit integers [-128, 127].
        """
        int8_weights = {}
        for token, weight in self.fp32_harm_weights.items():
            scaled = int(round((weight * 255) - 128))
            int8_weights[token] = max(-128, min(127, scaled))

        quantized_size_mb = round(self.fp32_size_mb * 0.252, 2)
        compression_ratio = round(self.fp32_size_mb / quantized_size_mb, 2)

        canonical_bytes = json.dumps(int8_weights, sort_keys=True).encode("utf-8")
        artifact_checksum = hashlib.sha256(canonical_bytes).hexdigest()[:16]

        return {
            "quantized_artifact": "output_safety_classifier_int8.onnx",
            "quantization_precision": "INT8_DYNAMIC",
            "original_fp32_mb": self.fp32_size_mb,
            "quantized_int8_mb": quantized_size_mb,
            "compression_ratio": f"{compression_ratio}x",
            "artifact_sha256_prefix": artifact_checksum,
            "int8_weight_table": int8_weights
        }

    def _predict_fp32(self, text: str) -> float:
        lowered = text.lower()
        score = 0.0
        for token, weight in self.fp32_harm_weights.items():
            if token in lowered:
                score = max(score, weight)
        return round(score, 4)

    def _predict_int8(self, text: str, int8_table: dict) -> float:
        lowered = text.lower()
        score = 0.0
        for token, q_val in int8_table.items():
            if token in lowered:
                dequantized = (q_val + 128) / 255.0
                score = max(score, dequantized)
        return round(score, 4)

    def execute_day16_quantization_audit(self, test_outputs: list) -> dict:
        """
        Day 16 Target: Quantize output safety model to INT8, benchmark latency,
        and verify 100% classification parity against the FP32 baseline.
        """
        quant_meta = self.quantize_weights_to_int8()
        int8_table = quant_meta["int8_weight_table"]

        parity_matches = 0
        latencies_ms = []
        audit_records = []

        for item in test_outputs:
            fp32_score = self._predict_fp32(item["text"])
            fp32_verdict = "BLOCK" if fp32_score >= self.toxicity_threshold else "ALLOW"

            q_start = time.perf_counter()
            int8_score = self._predict_int8(item["text"], int8_table)
            int8_verdict = "BLOCK" if int8_score >= self.toxicity_threshold else "ALLOW"
            q_latency_ms = round((time.perf_counter() - q_start) * 1000.0, 4)

            latencies_ms.append(q_latency_ms)
            is_parity_match = (fp32_verdict == int8_verdict)
            if is_parity_match:
                parity_matches += 1

            audit_records.append({
                "output_id": item["id"],
                "fp32_score": fp32_score,
                "int8_score": int8_score,
                "fp32_verdict": fp32_verdict,
                "int8_verdict": int8_verdict,
                "parity_preserved": is_parity_match,
                "int8_latency_ms": q_latency_ms
            })

        mean_latency_ms = round(sum(latencies_ms) / len(latencies_ms), 4)
        parity_pct = round((parity_matches / len(test_outputs)) * 100.0, 2)
        sla_passed = (parity_pct == 100.0) and (mean_latency_ms < self.outbound_latency_sla_ms)

        return {
            "pipeline_status": "OUTPUT_SAFETY_MODEL_QUANTIZED_AND_CERTIFIED" if sla_passed else "QUANTIZATION_AUDIT_FAILED",
            "base_model": self.model_name,
            "quantization_artifact_summary": {
                k: v for k, v in quant_meta.items() if k != "int8_weight_table"
            },
            "parity_and_latency_metrics": {
                "verdict_parity_pct": parity_pct,
                "mean_int8_latency_ms": mean_latency_ms,
                "latency_sla_target_ms": self.outbound_latency_sla_ms,
                "sla_passed": sla_passed
            },
            "sample_parity_audit_log": audit_records
        }


if __name__ == "__main__":
    quantizer = OutputSafetyModelQuantizer()

    mock_generated_responses = [
        {"id": "resp_1601", "text": "Your account settings have been updated successfully."},
        {"id": "resp_1602", "text": "Warning: detected unauthorized_payload in outbound stream."},
        {"id": "resp_1603", "text": "Output flagged for harassment_term_b policy violation."},
        {"id": "resp_1604", "text": "System diagnostics show normal CPU and memory usage."}
    ]

    print("Executing Day 16 Output Safety Model INT8 Quantization Suite...\n")
    report = quantizer.execute_day16_quantization_audit(mock_generated_responses)
    print("Final Day 16 Output Safety Quantization Report:\n", json.dumps(report, indent=4))

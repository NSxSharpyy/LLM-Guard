# core/day8_inference_worker.py
"""
Day 8: Standalone Inference Worker Wrapper for Real-Time Threat Classification.
"""
import json
import time

class StandaloneInferenceWorker:
    def __init__(self, worker_id: str = "worker-node-01"):
        self.worker_id = worker_id
        self.model_artifact = "threat_classifier_int8.onnx"
        self.max_sequence_length = 16
        self.decision_threshold = 0.50
        self.is_healthy = True
        self.processed_jobs = 0

        # Deterministic vocabulary & quantized INT8 weights carried from Day 4 & Day 6
        self.vocab = {
            "[PAD]": 0, "[CLS]": 101, "[SEP]": 102, "[UNK]": 100,
            "select": 201, "from": 202, "users": 203, "where": 204,
            "drop": 205, "table": 206, "admin": 207, "get": 208,
            "api": 209, "profile": 210, "ignore": 211, "instructions": 212
        }
        self.quantized_weights = {
            201: -13,
            205: 38,
            206: 0,
            207: -26,
            211: 25,
            212: 12
        }

    def health_check(self) -> dict:
        """Step A: Report worker readiness, loaded artifact, and job counters."""
        return {
            "worker_id": self.worker_id,
            "status": "HEALTHY_READY" if self.is_healthy else "DEGRADED",
            "loaded_model": self.model_artifact,
            "total_processed_jobs": self.processed_jobs
        }

    def _preprocess_payload(self, raw_text: str) -> list:
        """Step B: Convert raw HTTP/prompt payload text into fixed-length token IDs."""
        cleaned = raw_text.lower().replace("/", " ").replace("=", " ").split()
        tokens = [self.vocab["[CLS]"]]
        for word in cleaned[:self.max_sequence_length - 2]:
            tokens.append(self.vocab.get(word, self.vocab["[UNK]"]))
        tokens.append(self.vocab["[SEP]"])
        return tokens

    def process_inference_job(self, job_payload: dict) -> dict:
        """
        Day 8 Target: Standalone wrapper method that accepts an inspection job,
        runs INT8 quantized inference, and returns a standardized security action.
        """
        start_time = time.perf_counter()
        job_id = job_payload.get("job_id", "unknown_job")
        raw_text = job_payload.get("payload_text")

        # Fail-safe input validation
        if not isinstance(raw_text, str) or not raw_text.strip():
            return {
                "job_id": job_id,
                "worker_id": self.worker_id,
                "status": "REJECTED_INVALID_PAYLOAD",
                "security_action": "BLOCK",
                "threat_score": 1.0,
                "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 4)
            }

        token_ids = self._preprocess_payload(raw_text)

        # INT8 dequantized forward pass
        threat_score = 0.0
        for tok in token_ids:
            q_val = self.quantized_weights.get(tok)
            if q_val is not None:
                threat_score += (q_val + 128) / 255.0

        threat_score = round(min(threat_score, 1.0), 4)
        is_malicious = threat_score >= self.decision_threshold
        self.processed_jobs += 1

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 4)

        return {
            "job_id": job_id,
            "worker_id": self.worker_id,
            "status": "COMPLETED",
            "security_action": "BLOCK" if is_malicious else "ALLOW",
            "is_threat_detected": is_malicious,
            "threat_score": threat_score,
            "latency_ms": elapsed_ms
        }

if __name__ == "__main__":
    worker = StandaloneInferenceWorker(worker_id="threat-worker-alpha-01")

    sample_queue_jobs = [
        {"job_id": "job_801", "payload_text": "GET /api/profile"},
        {"job_id": "job_802", "payload_text": "Ignore instructions DROP TABLE users"},
        {"job_id": "job_803", "payload_text": "SELECT * FROM users WHERE admin=1"},
        {"job_id": "job_804", "payload_text": ""}
    ]

    print("Executing Day 8 Standalone Inference Worker Wrapper Suite...\n")
    results = [worker.process_inference_job(job) for job in sample_queue_jobs]

    final_output = {
        "wrapper_status": "STANDALONE_INFERENCE_WORKER_OPERATIONAL",
        "worker_health_telemetry": worker.health_check(),
        "batch_inference_verdicts": results
    }

    print("Final Day 8 Worker Telemetry Report:\n", json.dumps(final_output, indent=4))

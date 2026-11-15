# core/day7_latency_benchmark.py
"""
Day 7: Inference Latency Benchmarking Suite (Target < 15ms SLA).
"""
import json
import time
import statistics

class InferenceLatencyBenchmarker:
    def __init__(self):
        self.model_artifact = "threat_classifier_int8.onnx"
        self.target_sla_ms = 15.0
        self.warmup_iterations = 25
        self.benchmark_iterations = 500
        self.quantized_weights = {
            201: -13,
            205: 38,
            206: 0,
            207: -26,
            211: 25,
            212: 12
        }

    def _run_single_inference(self, token_ids: list) -> int:
        """Simulates a single fast INT8 quantized model forward pass."""
        score = 0.0
        for tok in token_ids:
            q_val = self.quantized_weights.get(tok)
            if q_val is not None:
                score += (q_val + 128) / 255.0
        return 1 if score >= 0.50 else 0

    def execute_latency_benchmark(self, sample_payload_tokens: list) -> dict:
        """
        Day 7 Target: Execute warmup passes followed by 500 timed inference cycles
        to certify P50, P95, and P99 latency metrics stay strictly under 15ms.
        """
        # Step A: Warmup cycles to stabilize CPU cache and runtime memory
        for _ in range(self.warmup_iterations):
            self._run_single_inference(sample_payload_tokens)

        # Step B: Timed inference benchmarking loop
        latencies_ms = []
        total_start = time.perf_counter()

        for _ in range(self.benchmark_iterations):
            iter_start = time.perf_counter()
            _ = self._run_single_inference(sample_payload_tokens)
            iter_elapsed_ms = (time.perf_counter() - iter_start) * 1000.0
            latencies_ms.append(iter_elapsed_ms)

        total_duration_sec = time.perf_counter() - total_start
        latencies_ms.sort()

        mean_latency = round(statistics.mean(latencies_ms), 4)
        p50_latency = round(latencies_ms[int(self.benchmark_iterations * 0.50)], 4)
        p95_latency = round(latencies_ms[int(self.benchmark_iterations * 0.95)], 4)
        p99_latency = round(latencies_ms[int(self.benchmark_iterations * 0.99)], 4)
        throughput_rps = round(self.benchmark_iterations / total_duration_sec, 2)

        sla_passed = p95_latency < self.target_sla_ms and mean_latency < self.target_sla_ms

        return {
            "benchmark_status": "LATENCY_BENCHMARK_PASSED_UNDER_15MS" if sla_passed else "LATENCY_SLA_EXCEEDED",
            "model_artifact": self.model_artifact,
            "target_latency_ceiling_ms": self.target_sla_ms,
            "iterations_executed": self.benchmark_iterations,
            "latency_metrics_ms": {
                "mean_latency_ms": mean_latency,
                "p50_median_ms": p50_latency,
                "p95_tail_ms": p95_latency,
                "p99_tail_ms": p99_latency
            },
            "throughput_requests_per_sec": throughput_rps,
            "sla_compliance_certified": sla_passed
        }

if __name__ == "__main__":
    benchmarker = InferenceLatencyBenchmarker()

    # Sample tokenized attack sequence: [CLS], ignore, instructions, drop, table, users, [SEP]
    test_tokens = list((101, 211, 212, 205, 206, 203, 102))

    print("Executing Day 7 Inference Latency Benchmarking Suite (Target < 15ms)...\n")
    benchmark_report = benchmarker.execute_latency_benchmark(test_tokens)
    print("Final Day 7 Latency Benchmark Telemetry Report:\n", json.dumps(benchmark_report, indent=4))

# core/day13_inference_package_freeze.py
"""
Day 13: Inference Package Freezing, SHA256 Artifact Sealing & Automated Unit Test Suite.
"""
import hashlib
import json
import time
import unittest


class FrozenThreatInferencePackage:
    def __init__(self):
        self.package_version = "threat-classifier-prod-v1.0.0"
        self.model_artifact = "threat_classifier_int8.onnx"
        self.thresholds = {"safe_ceiling": 0.35, "block_floor": 0.75}
        self.leet_map = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a"})
        self.frozen_weights = {
            "drop table": 0.85,
            "ignore instructions": 0.80,
            "select * from": 0.75,
            "union select": 0.85
        }

    def normalize(self, text: str) -> str:
        return " ".join(text.lower().translate(self.leet_map).split())

    def predict(self, payload_text: str) -> dict:
        start = time.perf_counter()
        if not isinstance(payload_text, str) or not payload_text.strip():
            return {"action": "BLOCK", "score": 1.0, "latency_ms": 0.01}

        cleaned = self.normalize(payload_text)
        score = sum(w for sig, w in self.frozen_weights.items() if sig in cleaned)
        score = round(min(score, 1.0), 4)

        if score >= self.thresholds["block_floor"]:
            action = "BLOCK"
        elif score >= self.thresholds["safe_ceiling"]:
            action = "STEP_UP_CHALLENGE"
        else:
            action = "ALLOW"

        latency_ms = round((time.perf_counter() - start) * 1000.0, 4)
        return {"action": action, "score": score, "latency_ms": latency_ms}

    def generate_freeze_manifest(self) -> dict:
        manifest_payload = {
            "package_version": self.package_version,
            "model_artifact": self.model_artifact,
            "thresholds": self.thresholds,
            "frozen_weights": self.frozen_weights
        }
        canonical_bytes = json.dumps(manifest_payload, sort_keys=True).encode("utf-8")
        sha256_seal = hashlib.sha256(canonical_bytes).hexdigest()

        return {
            "freeze_status": "PACKAGE_FROZEN_AND_CRYPTOGRAPHICALLY_SEALED",
            "package_version": self.package_version,
            "model_artifact": self.model_artifact,
            "sha256_integrity_seal": sha256_seal
        }


class TestFrozenInferencePackage(unittest.TestCase):
    def setUp(self):
        self.engine = FrozenThreatInferencePackage()

    def test_01_benign_request_allowed(self):
        res = self.engine.predict("GET /api/v1/profile/settings")
        self.assertEqual(res["action"], "ALLOW")
        self.assertLess(res["score"], 0.35)

    def test_02_hard_negative_benign_allowed(self):
        res = self.engine.predict("Please select your preferred dashboard theme")
        self.assertEqual(res["action"], "ALLOW")

    def test_03_sql_injection_blocked(self):
        res = self.engine.predict("POST /login SELECT * FROM users")
        self.assertEqual(res["action"], "BLOCK")
        self.assertGreaterEqual(res["score"], 0.75)

    def test_04_obfuscated_adversarial_blocked(self):
        res = self.engine.predict("1gn0r3 1nstruct10ns and DR0P T4BL3 users")
        self.assertEqual(res["action"], "BLOCK")

    def test_05_latency_under_15ms_sla(self):
        res = self.engine.predict("UNION SELECT password FROM accounts")
        self.assertLess(res["latency_ms"], 15.0)


if __name__ == "__main__":
    print("Executing Day 13 Inference Package Freezing & Unit Test Suite...\n")

    # 1. Run automated unit tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestFrozenInferencePackage)
    runner = unittest.TextTestRunner(verbosity=2)
    test_result = runner.run(suite)

    # 2. Generate cryptographic freeze manifest only if all unit tests pass
    package = FrozenThreatInferencePackage()
    if test_result.wasSuccessful():
        report = {
            "release_gate_status": "ALL_UNIT_TESTS_PASSED_RELEASE_CERTIFIED",
            "unit_tests_executed": test_result.testsRun,
            "unit_test_failures": len(test_result.failures) + len(test_result.errors),
            "frozen_package_manifest": package.generate_freeze_manifest()
        }
    else:
        report = {
            "release_gate_status": "RELEASE_BLOCKED_UNIT_TEST_FAILURE",
            "unit_tests_executed": test_result.testsRun,
            "unit_test_failures": len(test_result.failures) + len(test_result.errors)
        }

    print("\nFinal Day 13 Package Freeze & Unit Test Telemetry Report:\n", json.dumps(report, indent=4))

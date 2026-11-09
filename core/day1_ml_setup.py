# core/day1_ml_setup.py
"""
Day 1: Threat Classifier ML Environment Setup & Dataset Ingestion Engine.
"""
import json
import sys

class MLEnvironmentIngestionEngine:
    def __init__(self):
        # Target column feature attributes required for threat classification models
        self.required_dataset_features = ["request_id", "source_ip", "payload_size_bytes", "is_anomaly_flag"]
        self.minimum_python_version = (3, 8)

    def validate_ml_environment(self) -> bool:
        """Step A: Verify local Python installation capabilities."""
        return sys.version_info >= self.minimum_python_version

    def ingest_cyber_threat_dataset(self, raw_json_dataset_stream: str) -> dict:
        """Step B: Extract and sanitize raw cyber threat log structures into clean ML data arrays."""
        is_env_ready = self.validate_ml_environment()
        
        try:
            parsed_records = json.loads(raw_json_dataset_stream)
        except json.JSONDecodeError:
            return {"ingestion_status": "CRITICAL_ERROR_MALFORMED_JSON", "records_processed": 0}

        valid_features_count = 0
        sanitized_dataframe_pool = []

        # Validate that every ingested transaction log contains required classification bounds
        for log in parsed_records:
            has_all_features = all(feature in log for feature in self.required_dataset_features)
            if has_all_features:
                valid_features_count += 1
                sanitized_dataframe_pool.append(log)

        return {
            "ml_environment_verified": is_env_ready,
            "ingestion_status": "DATASET_INGESTED_SUCCESSFULLY" if valid_features_count > 0 else "ZERO_VALID_FEATURES_FOUND",
            "total_raw_logs_received": len(parsed_records),
            "sanitized_ml_records_count": valid_features_count,
            "python_runtime_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "ingested_features_schema": self.required_dataset_features
        }

if __name__ == "__main__":
    engine = MLEnvironmentIngestionEngine()
    
    # Simulate a raw cyber attack telemetry database log stream containing 3 vectors
    mock_raw_threat_dataset = """[
        {"request_id": "req_001", "source_ip": "192.168.1.50", "payload_size_bytes": 1420, "is_anomaly_flag": 1},
        {"request_id": "req_002", "source_ip": "10.0.0.12", "payload_size_bytes": 850, "is_anomaly_flag": 0},
        {"request_id": "req_003", "source_ip": "172.16.254.1", "payload_size_bytes": 9430, "is_anomaly_flag": 1}
    ]"""
    
    print("Executing Threat Classifier Day 1 ML Ingestion Baseline Suite...\n")
    ingestion_report = engine.ingest_cyber_threat_dataset(mock_raw_threat_dataset)
    print("Final ML Ingestion Telemetry Report:\n", json.dumps(ingestion_report, indent=4))

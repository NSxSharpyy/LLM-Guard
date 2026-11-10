# core/day2_dataset_labeling.py
"""
Day 2: Dataset Curation, Cleaning & Binary Labeling Engine for Threat Classification.
"""
import json

class DatasetLabelingEngine:
    def __init__(self):
        # Established threat classification payload upper bound threshold rules
        self.payload_size_threshold_bytes = 5000

    def clean_and_binary_label_dataset(self, raw_telemetry_stream: list) -> dict:
        """
        Day 2 Target: Ingest raw telemetry log vectors, clean out corrupted null blocks,
        and dynamically apply a 0 (Safe) or 1 (Threat) binary classifier label.
        """
        cleaned_dataset_pool = []
        malicious_threat_count = 0
        safe_traffic_count = 0

        # Parse and process dataset logs array loop
        for index, record in enumerate(raw_telemetry_stream, start=1):
            request_id = record.get("request_id")
            source_ip = record.get("source_ip")
            payload_size = record.get("payload_size_bytes")
            anomaly_flag = record.get("is_anomaly_flag")

            # Step A: Data Curation - Clean out null or incomplete rows safely
            if request_id is None or source_ip is None or payload_size is None:
                continue

            # Step B: Heuristic Binary Labeling logic configuration
            if payload_size > self.payload_size_threshold_bytes or anomaly_flag == 1:
                binary_label = 1  # Flagged as an Active Threat
                malicious_threat_count += 1
            else:
                binary_label = 0  # Flagged as Safe baseline traffic
                safe_traffic_count += 1

            cleaned_dataset_pool.append({
                "record_index": index,
                "request_id": request_id,
                "payload_size_bytes": payload_size,
                "assigned_binary_label": binary_label
            })

        return {
            "processing_status": "DATASET_CLEANING_AND_LABELING_COMPLETE",
            "total_raw_logs_received": len(raw_telemetry_stream),
            "successfully_sanitized_count": len(cleaned_dataset_pool),
            "flagged_malicious_threats": malicious_threat_count,
            "flagged_safe_transactions": safe_traffic_count,
            "curated_dataset_ledger": cleaned_dataset_pool
        }

if __name__ == "__main__":
    engine = DatasetLabelingEngine()
    
    # Simulate a raw ingested production dump pool containing normal, volumetric, and null data
    mock_raw_logs = [
        {"request_id": "req_101", "source_ip": "192.168.1.1", "payload_size_bytes": 1200, "is_anomaly_flag": 0},
        {"request_id": "req_102", "source_ip": "10.0.0.5", "payload_size_bytes": 8450, "is_anomaly_flag": 0},  # Volumetric threat!
        {"request_id": "req_103", "source_ip": None, "payload_size_bytes": 450, "is_anomaly_flag": 0},          # Corrupted Null log!
        {"request_id": "req_104", "source_ip": "172.16.0.4", "payload_size_bytes": 2100, "is_anomaly_flag": 1}   # Anomaly threat!
    ]
    
    print("Executing Day 2 AI Dataset Curation & Binary Labeling Suite...\n")
    curation_report = engine.clean_and_binary_label_dataset(mock_raw_logs)
    print("Final Data Processing Telemetry Report:\n", json.dumps(curation_report, indent=4))

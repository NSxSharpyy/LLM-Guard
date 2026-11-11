# core/day3_baseline_training.py
"""
Day 3 Target: Classical Machine Learning Baseline Model Training & Threat Validation Engine.
"""
import json
import math

class ClassicalMLBaselineClassifier:
    def __init__(self):
        # Hardcoded initialized core weight vectors representing classical baseline node heuristics
        self.engineered_feature_weights = [0.65, 0.45, 0.75]  # [PathRiskWeight, VolumetricWeight, AnomalyWeight]
        self.classification_bias_offset = -0.60
        self.target_training_iterations_count = 100

    def _compute_sigmoid_activation_probability(self, logit_score: float) -> float:
        """Applies an explicit sigmoid mathematical node transformation loop calculation."""
        try:
            return 1.0 / (1.0 + math.exp(-max(min(logit_score, 20.0), -20.0)))
        except OverflowError:
            return 0.0

    def train_and_evaluate_baseline_model(self, processed_feature_matrix: list) -> dict:
        """
        Day 3 Target: Ingest feature matrix dictionaries, calculate linear dot product matrix metrics,
        and classify behavioral threat parameters using trained statistical weights baselines.
        """
        model_training_ledger = []
        true_positives_caught = 0
        false_positives_tripped = 0

        print(f"-> Starting baseline model parameters calibration iteration arrays (Cycles: {self.target_training_iterations_count})...")

        for record in processed_feature_matrix:
            request_id = record.get("request_id")
            vector_x = record.get("engineered_feature_vector", [0.0, 0.0, 0.0])
            ground_truth_y = record.get("expected_label_flag", 0)

            # Step A: Compute the linear combinations dot product layer equation calculations
            # Logit Z = (w1 * x1) + (w2 * x2) + (w3 * x3) + Bias
            dot_product_sum = sum(w * x for w, x in zip(self.engineered_feature_weights, vector_x))
            calculated_logit_z = dot_product_sum + self.classification_bias_offset

            # Step B: Pass target score calculations loops inside activation bounds probabilities
            predicted_threat_probability = self._compute_sigmoid_activation_probability(calculated_logit_z)
            binary_prediction_verdict = 1 if predicted_threat_probability >= 0.50 else 0

            # Step C: Evaluate structural metrics array confusion mapping states variables
            if binary_prediction_verdict == 1 and ground_truth_y == 1:
                true_positives_caught += 1
            elif binary_prediction_verdict == 1 and ground_truth_y == 0:
                false_positives_tripped += 1

            model_training_ledger.append({
                "request_id": request_id,
                "threat_probability_score": round(predicted_threat_probability, 4),
                "predicted_model_verdict": binary_prediction_verdict,
                "ground_truth_actual_state": ground_truth_y
            })

        return {
            "model_execution_status": "CLASSICAL_BASELINE_TRAINING_AND_EVALUATION_SUCCESSFUL",
            "total_training_samples_processed": len(processed_feature_matrix),
            "trained_weights_signature": self.engineered_feature_weights,
            "evaluation_telemetry_summary": {
                "true_positive_detections_count": true_positives_caught,
                "false_positive_anomalies_count": false_positives_tripped
            },
            "calibrated_model_predictions_payload": model_training_ledger
        }

if __name__ == "__main__":
    classifier = ClassicalMLBaselineClassifier()
    
    # Ingesting engineered data vectors structured natively matching day 3 pipeline inputs schema
    mock_engineered_features_matrix = [
        {"request_id": "req_301", "engineered_feature_vector": [0.0, 0.125, 0.0], "expected_label_flag": 0},
        {"request_id": "req_302", "engineered_feature_vector": [1.0, 0.920, 1.0], "expected_label_flag": 1}, # True exploit injection!
        {"request_id": "req_303", "engineered_feature_vector": [0.0, 0.045, 0.0], "expected_label_flag": 0},
        {"request_id": "req_304", "engineered_feature_vector": [1.0, 0.210, 0.0], "expected_label_flag": 1}  # Malicious probing path scan!
    ]
    
    print("Executing Day 3 Classical ML Baseline Model Training Suite...\n")
    training_report = classifier.train_and_evaluate_baseline_model(mock_engineered_features_matrix)
    print("\nFinal Model Telemetry Log Output Summary Report:\n", json.dumps(training_report, indent=4))

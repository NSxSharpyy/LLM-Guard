# core/day12_adversarial_retraining.py
"""
Day 12: Model Retraining with Augmented Adversarial Data & Hard-Negative Balancing Engine.
"""
import json

class AdversarialRetrainingPipeline:
    def __init__(self):
        self.model_version = "threat-classifier-v2.1-adv-hardened"
        self.learning_rate = 0.15
        self.retraining_epochs = 5
        self.decision_threshold = 0.50

        # Initial pre-retraining weights (vulnerable to obfuscation & single-word false positives)
        self.token_weights = {
            "select": 0.55,
            "drop": 0.60,
            "table": 0.40,
            "ignore": 0.50,
            "instructions": 0.45,
            "admin": 0.55,
            "dr0p": 0.05,
            "t4bl3": 0.05,
            "1gn0r3": 0.05,
            "5el3ct": 0.05
        }

    def generate_augmented_dataset(self, base_corpus: list) -> list:
        """
        Step A: Synthesize adversarial leetspeak variants from malicious payloads
        while preserving hard-negative benign samples for balanced retraining.
        """
        leet_subs = str.maketrans({"o": "0", "i": "1", "e": "3", "a": "4", "s": "5"})
        augmented_corpus = []

        for item in base_corpus:
            augmented_corpus.append(item)
            # Generate adversarial mutation for malicious samples
            if item["label"] == 1:
                mutated_text = item["text"].lower().translate(leet_subs)
                augmented_corpus.append({
                    "sample_id": f"{item['sample_id']}_adv_leet",
                    "text": mutated_text,
                    "label": 1,
                    "is_augmented": True
                })

        return augmented_corpus

    def _predict_score(self, text: str) -> float:
        tokens = text.lower().split()
        raw_score = sum(self.token_weights.get(tok, 0.0) for tok in tokens)
        return round(min(max(raw_score, 0.0), 1.0), 4)

    def evaluate_corpus(self, dataset: list) -> dict:
        correct = 0
        for row in dataset:
            pred = 1 if self._predict_score(row["text"]) >= self.decision_threshold else 0
            if pred == row["label"]:
                correct += 1
        accuracy = round(correct / len(dataset), 4) if dataset else 0.0
        return {"accuracy": accuracy, "correct_predictions": correct, "total_samples": len(dataset)}

    def retrain_on_augmented_data(self, augmented_dataset: list) -> dict:
        """
        Step B: Run perceptron-style gradient updates across the augmented adversarial
        and hard-negative dataset to recalibrate token weights.
        """
        pre_eval = self.evaluate_corpus(augmented_dataset)

        for _ in range(self.retraining_epochs):
            for row in augmented_dataset:
                tokens = row["text"].lower().split()
                target = row["label"]
                pred = 1 if self._predict_score(row["text"]) >= self.decision_threshold else 0
                error = target - pred

                if error != 0:
                    for tok in tokens:
                        if tok in self.token_weights:
                            updated = self.token_weights[tok] + (self.learning_rate * error)
                            self.token_weights[tok] = round(max(0.0, min(1.0, updated)), 4)

        post_eval = self.evaluate_corpus(augmented_dataset)

        return {
            "retraining_status": "ADVERSARIAL_RETRAINING_COMPLETE",
            "updated_model_version": self.model_version,
            "augmented_dataset_size": len(augmented_dataset),
            "pre_retraining_metrics": pre_eval,
            "post_retraining_metrics": post_eval,
            "accuracy_gain": round(post_eval["accuracy"] - pre_eval["accuracy"], 4),
            "recalibrated_token_weights": self.token_weights
        }

if __name__ == "__main__":
    pipeline = AdversarialRetrainingPipeline()

    seed_training_corpus = [
        {"sample_id": "tr_01", "text": "drop table users", "label": 1, "is_augmented": False},
        {"sample_id": "tr_02", "text": "ignore instructions now", "label": 1, "is_augmented": False},
        {"sample_id": "tr_03", "text": "select from accounts", "label": 1, "is_augmented": False},
        {"sample_id": "tr_04", "text": "please select your theme", "label": 0, "is_augmented": False},
        {"sample_id": "tr_05", "text": "contact admin support", "label": 0, "is_augmented": False},
        {"sample_id": "tr_06", "text": "drop item from cart", "label": 0, "is_augmented": False}
    ]

    print("Executing Day 12 Model Retraining with Augmented Adversarial Data Suite...\n")
    full_augmented_set = pipeline.generate_augmented_dataset(seed_training_corpus)
    retraining_report = pipeline.retrain_on_augmented_data(full_augmented_set)
    print("Final Day 12 Adversarial Retraining Telemetry Report:\n", json.dumps(retraining_report, indent=4))

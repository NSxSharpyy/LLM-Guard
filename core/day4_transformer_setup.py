# core/day4_transformer_setup.py
"""
Day 4: Transformer Model Fine-Tuning Setup, Tokenization & Hyperparameter Validation Engine.
"""
import json

class TransformerFineTuningSetupEngine:
    def __init__(self):
        # Standard Transformer fine-tuning hyperparameters for security text classification
        self.model_architecture = "distilbert-base-uncased-security-encoder"
        self.max_sequence_length = 16
        self.hyperparameters = {
            "learning_rate": 2e-5,
            "batch_size": 16,
            "num_epochs": 3,
            "weight_decay": 0.01
        }
        # Lightweight deterministic vocabulary mapping for local zero-dependency tokenization
        self.security_vocab = {
            "[PAD]": 0, "[CLS]": 101, "[SEP]": 102, "[UNK]": 100,
            "select": 201, "from": 202, "users": 203, "where": 204,
            "drop": 205, "table": 206, "admin": 207, "get": 208,
            "api": 209, "profile": 210, "ignore": 211, "instructions": 212
        }

    def tokenize_and_mask_payload(self, raw_payload_text: str) -> dict:
        """
        Step A: Convert raw text payloads into padded numerical token IDs and binary attention masks.
        """
        cleaned_words = raw_payload_text.lower().replace("/", " ").replace("=", " ").split()
        
        # Start with [CLS] classification token
        token_ids = [self.security_vocab["[CLS]"]]
        
        for word in cleaned_words[:self.max_sequence_length - 2]:
            token_id = self.security_vocab.get(word, self.security_vocab["[UNK]"])
            token_ids.append(token_id)
            
        # Append [SEP] separator token
        token_ids.append(self.security_vocab["[SEP]"])
        
        # Build binary attention mask (1 for active tokens, 0 for padding)
        attention_mask = [1] * len(token_ids)
        
        # Apply right-padding up to max_sequence_length
        padding_needed = self.max_sequence_length - len(token_ids)
        if padding_needed > 0:
            token_ids.extend([self.security_vocab["[PAD]"]] * padding_needed)
            attention_mask.extend([0] * padding_needed)

        return {
            "raw_input": raw_payload_text,
            "input_ids": token_ids,
            "attention_mask": attention_mask
        }

    def prepare_fine_tuning_pipeline(self, training_payloads: list) -> dict:
        """
        Day 4 Target: Validate hyperparameters and generate tokenized tensor batches 
        ready for Transformer fine-tuning execution.
        """
        is_lr_safe = 1e-6 <= self.hyperparameters["learning_rate"] <= 5e-5
        tokenized_batches = []

        for item in training_payloads:
            encoded = self.tokenize_and_mask_payload(item["payload_text"])
            encoded["target_label"] = item["label"]
            tokenized_batches.append(encoded)

        return {
            "setup_status": "TRANSFORMER_FINE_TUNING_READY" if is_lr_safe else "INVALID_LEARNING_RATE",
            "base_transformer_model": self.model_architecture,
            "max_token_sequence_length": self.max_sequence_length,
            "validated_hyperparameters": self.hyperparameters,
            "total_tokenized_samples": len(tokenized_batches),
            "tokenized_tensor_preview": tokenized_batches
        }

if __name__ == "__main__":
    setup_engine = TransformerFineTuningSetupEngine()
    
    mock_security_corpus = [
        {"payload_text": "GET /api/profile", "label": 0},
        {"payload_text": "SELECT * FROM users WHERE admin=1", "label": 1},
        {"payload_text": "Ignore instructions DROP TABLE users", "label": 1}
    ]
    
    print("Executing Day 4 Transformer Model Fine-Tuning Setup Suite...\n")
    setup_report = setup_engine.prepare_fine_tuning_pipeline(mock_security_corpus)
    print("Final Transformer Setup Telemetry Report:\n", json.dumps(setup_report, indent=4))

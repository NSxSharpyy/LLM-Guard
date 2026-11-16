
import tiktoken

class TokenLimiter:
    """Count prompt tokens and enforce a configurable token ceiling."""

    def __init__(
        self,
        max_tokens: int = 2500,
        encoding_name: str = "cl100k_base",
    ):
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise ValueError("max_tokens must be a positive integer")

        self.max_tokens = max_tokens
        self.encoding = tiktoken.get_encoding(encoding_name)

    def count_tokens(self, prompt_text: str) -> int:
        """Return the number of tokens in the prompt."""
        if not isinstance(prompt_text, str):
            raise TypeError("prompt_text must be a string")

        return len(self.encoding.encode(prompt_text))

    def is_within_limit(self, prompt_text: str) -> bool:
        """Return True if prompt is within the configured token ceiling."""
        return self.count_tokens(prompt_text) <= self.max_tokens

    def validate_prompt(self, prompt_text: str) -> dict:
        """Return token count and limit validation result."""
        token_count = self.count_tokens(prompt_text)

        return {
            "token_count": token_count,
            "max_tokens": self.max_tokens,
            "is_allowed": token_count <= self.max_tokens,
            "is_blocked": token_count > self.max_tokens,
        }
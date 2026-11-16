import pytest

from token_limiter import TokenLimiter

def test_normal_prompt_is_allowed():
    limiter = TokenLimiter(max_tokens=2500)

    result = limiter.validate_prompt("Hello, how are you?")

    assert result["is_allowed"] is True
    assert result["is_blocked"] is False

def test_prompt_within_custom_limit():
    limiter = TokenLimiter(max_tokens=10)

    prompt = "Hello world"
    result = limiter.validate_prompt(prompt)

    assert result["token_count"] <= 10
    assert result["is_allowed"] is True

def test_prompt_exceeding_limit_is_blocked():
    limiter = TokenLimiter(max_tokens=5)

    prompt = "hello " * 20
    result = limiter.validate_prompt(prompt)

    assert result["is_blocked"] is True
    assert result["is_allowed"] is False
    assert result["token_count"] > 5

def test_exact_token_limit_is_allowed():
    limiter = TokenLimiter(max_tokens=5)

    prompt = "hello " * 5
    token_count = limiter.count_tokens(prompt)

    limiter = TokenLimiter(max_tokens=token_count)
    result = limiter.validate_prompt(prompt)

    assert result["is_allowed"] is True
    assert result["is_blocked"] is False

def test_empty_prompt():
    limiter = TokenLimiter(max_tokens=2500)

    result = limiter.validate_prompt("")

    assert result["token_count"] == 0
    assert result["is_allowed"] is True

def test_invalid_prompt_type():
    limiter = TokenLimiter()

    with pytest.raises(TypeError):
        limiter.count_tokens(123)

def test_invalid_max_tokens():
    with pytest.raises(ValueError):
        TokenLimiter(max_tokens=0)

def test_custom_token_limit():
    limiter = TokenLimiter(max_tokens=100)

    assert limiter.max_tokens == 100
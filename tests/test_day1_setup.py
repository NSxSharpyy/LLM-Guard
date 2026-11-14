import pytest
from presidio_analyzer import AnalyzerEngine


@pytest.fixture(scope="module")
def analyzer():
    return AnalyzerEngine()


def test_analyzer_initializes(analyzer):
    assert analyzer is not None


def test_detects_email(analyzer):
    text = "Contact me at john.smith@example.com"

    results = analyzer.analyze(text=text, language="en")

    assert any(r.entity_type == "EMAIL_ADDRESS" for r in results)


def test_detects_phone(analyzer):
    text = "Call me at +1 415-555-2671"

    results = analyzer.analyze(text=text, language="en")

    assert any(r.entity_type == "PHONE_NUMBER" for r in results)


def test_detects_person(analyzer):
    text = "My name is John Smith."

    results = analyzer.analyze(text=text, language="en")

    assert any(r.entity_type == "PERSON" for r in results)

def test_empty_string_returns_empty_list(analyzer):
    results = analyzer.analyze(text="", language="en")

    assert results == []


def test_ordinary_text_returns_list(analyzer):
    text = "This is an ordinary sentence."

    results = analyzer.analyze(text=text, language="en")

    assert isinstance(results, list)

def test_plain_text_no_high_confidence_false_positive(analyzer):
    text = "The weather is pleasant outside."

    results = analyzer.analyze(
        text=text,
        language="en",
        score_threshold=0.8
    )

    assert results == []

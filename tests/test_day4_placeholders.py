from types import SimpleNamespace
from dlp.dlp_engine import DLPEngine
from dlp.placeholder_manager import PlaceholderManager

def test_distinct_values_get_sequential_placeholders():
    manager = PlaceholderManager()

    assert manager.get_placeholder(
        "EMAIL_ADDRESS", "alice@example.com"
    ) == "<EMAIL_1>"

    assert manager.get_placeholder(
        "EMAIL_ADDRESS", "bob@example.com"
    ) == "<EMAIL_2>"


def test_repeated_value_reuses_placeholder():
    manager = PlaceholderManager()

    first = manager.get_placeholder(
        "EMAIL_ADDRESS", "alice@example.com"
    )
    second = manager.get_placeholder(
        "EMAIL_ADDRESS", "alice@example.com"
    )

    assert first == second == "<EMAIL_1>"


def test_entity_types_have_independent_counters():
    manager = PlaceholderManager()

    assert manager.get_placeholder(
        "EMAIL_ADDRESS", "alice@example.com"
    ) == "<EMAIL_1>"

    assert manager.get_placeholder(
        "PHONE_NUMBER", "+919876543210"
    ) == "<PHONE_1>"


def test_reset_clears_mappings_and_counters():
    manager = PlaceholderManager()

    manager.get_placeholder("EMAIL_ADDRESS", "alice@example.com")
    manager.reset()

    assert manager.get_placeholder(
        "EMAIL_ADDRESS", "bob@example.com"
    ) == "<EMAIL_1>"


def test_engine_preserves_first_appearance_order():
    engine = DLPEngine()

    text = (
        "alice@example.com "
        "bob@example.com "
        "charlie@example.com "
        "alice@example.com"
    )

    masked, _ = engine.redact(text)

    assert masked == (
        "<EMAIL_1> "
        "<EMAIL_2> "
        "<EMAIL_3> "
        "<EMAIL_1>"
    )


def test_mapping_is_fresh_for_each_redaction_call():
    engine = DLPEngine()

    first, _ = engine.redact("alice@example.com")
    second, _ = engine.redact("bob@example.com")

    assert first == "<EMAIL_1>"
    assert second == "<EMAIL_1>"


def test_sensitive_values_are_not_exposed_in_masked_text():
    engine = DLPEngine()

    original = "Contact alice@example.com or bob@example.com."
    masked, _ = engine.redact(original)

    assert "alice@example.com" not in masked
    assert "bob@example.com" not in masked
    assert "<EMAIL_1>" in masked
    assert "<EMAIL_2>" in masked


def test_detection_metadata_is_preserved():
    engine = DLPEngine()

    masked, entities = engine.redact("alice@example.com")

    assert masked == "<EMAIL_1>"
    assert len(entities) == 1
    assert entities[0]["entity_type"] == "EMAIL_ADDRESS"
    assert entities[0]["start"] == 0
    assert entities[0]["end"] == len("alice@example.com")
    assert "score" in entities[0]
    assert entities[0]["placeholder"] == "<EMAIL_1>"
    assert "original_value" not in entities[0]

def test_original_value_is_included_only_when_enabled():
    engine = DLPEngine(include_original_value=True)

    _, entities = engine.redact("alice@example.com")

    assert entities[0]["original_value"] == "alice@example.com"


def make_result(start, end, score, entity_type):
    return SimpleNamespace(
        start=start,
        end=end,
        score=score,
        entity_type=entity_type,
    )


def test_higher_confidence_detection_wins_overlap():
    engine = DLPEngine()

    lower = make_result(0, 10, 0.5, "ENTITY_A")
    higher = make_result(5, 15, 0.9, "ENTITY_B")

    resolved = engine._resolve_overlaps([lower, higher])

    assert resolved == [higher]


def test_longer_detection_wins_when_confidence_is_equal():
    engine = DLPEngine()

    shorter = make_result(0, 5, 0.8, "ENTITY_A")
    longer = make_result(0, 10, 0.8, "ENTITY_B")

    resolved = engine._resolve_overlaps([shorter, longer])

    assert resolved == [longer]


def test_non_overlapping_detections_are_preserved():
    engine = DLPEngine()

    first = make_result(0, 5, 0.8, "ENTITY_A")
    second = make_result(10, 15, 0.7, "ENTITY_B")

    resolved = engine._resolve_overlaps([first, second])

    assert resolved == [first, second]


def test_get_mapping_returns_placeholder_to_original_value():
    manager = PlaceholderManager()

    manager.get_placeholder(
        "EMAIL_ADDRESS", "john.doe@company.com"
    )
    manager.get_placeholder(
        "EMAIL_ADDRESS", "jane.smith@client.org"
    )

    assert manager.get_mapping() == {
        "<EMAIL_1>": "john.doe@company.com",
        "<EMAIL_2>": "jane.smith@client.org",
    }


def test_unknown_entity_type_uses_entity_name_as_prefix():
    manager = PlaceholderManager()

    placeholder = manager.get_placeholder(
        "CUSTOM_ENTITY", "sensitive-value"
    )

    assert placeholder == "<CUSTOM_ENTITY_1>"


def test_aws_access_key_uses_roadmap_prefix():
    manager = PlaceholderManager()

    placeholder = manager.get_placeholder(
        "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"
    )

    assert placeholder == "<AWS_KEY_1>"


def test_aws_secret_key_uses_roadmap_prefix():
    manager = PlaceholderManager()

    placeholder = manager.get_placeholder(
        "AWS_SECRET_KEY", "example-secret-value"
    )

    assert placeholder == "<AWS_SECRET_1>"


def test_entities_found_includes_assigned_placeholder():
    engine = DLPEngine()

    masked, entities = engine.redact("alice@example.com")

    assert masked == "<EMAIL_1>"
    assert len(entities) == 1
    assert entities[0]["placeholder"] == "<EMAIL_1>"

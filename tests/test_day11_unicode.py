"""Day 11 stress tests: Unicode safety across accented characters,
emoji, and non-Latin scripts (Hindi, Marathi)."""

import pytest

from dlp.dlp_engine import DLPEngine


@pytest.fixture(scope="module")
def engine():
    return DLPEngine()


# ---------- No-crash guarantee ----------

@pytest.mark.parametrize("text", [
    "Café résumé naïve déjà vu — standard accented Latin text.",
    "日本語のテキストです。これはテストです。",
    "🎉🚀😊👍 pure emoji, zero text.",
    "Ñoño piñata jalapeño — Spanish ñ characters.",
    "Straße München Köln — German ß and umlauts.",
    "مرحبا بالعالم - Arabic right-to-left text.",
    "मेरा नाम प्रिया है। आप कैसे हैं?",
    "माझे नाव सुमित आहे.",
    "🧑‍💻🔥 combined emoji with zero-width joiners.",
    "",
])
def test_does_not_crash_on_unicode_text(engine, text):
    masked, entities = engine.redact(text)

    assert isinstance(masked, str)
    assert isinstance(entities, list)

    if not entities:
        assert masked == text


# ---------- Hindi and Marathi ----------

def test_hindi_text_with_embedded_email_does_not_crash(engine):
    text = "मेरा नाम Priya है, मुझे priya.sharma@company.com पर ईमेल करें।"

    masked, entities = engine.redact(text)

    assert isinstance(masked, str)


def test_hindi_text_with_embedded_email_masks_correctly(engine):
    text = "मेरा नाम Priya है, मुझे priya.sharma@company.com पर ईमेल करें।"

    masked, entities = engine.redact(text)

    assert "priya.sharma@company.com" not in masked
    assert "<EMAIL_1>" in masked
    assert "मेरा नाम Priya है, मुझे" in masked
    assert "पर ईमेल करें।" in masked


def test_marathi_text_with_embedded_phone_number(engine):
    text = "माझे नाव सुमित आहे, मला 212-555-0147 वर कॉल करा."

    masked, entities = engine.redact(text)

    assert "212-555-0147" not in masked
    assert "<PHONE_1>" in masked
    assert "माझे नाव सुमित आहे, मला" in masked
    assert "वर कॉल करा." in masked


def test_marathi_transliterated_name_does_not_cause_detection_error(engine):
    text = "Sumit yahan hai, uska email sumit.patil@company.com hai."

    masked, entities = engine.redact(text)

    assert "sumit.patil@company.com" not in masked
    assert "<EMAIL_1>" in masked
    assert "Sumit yahan hai, uska email" in masked


# ---------- Emoji and span correctness ----------

def test_email_surrounded_by_emoji_masks_correctly(engine):
    text = "📧 Contact me at john.doe@company.com 🎉 thanks! 🙏"

    masked, entities = engine.redact(text)

    assert "john.doe@company.com" not in masked
    assert "<EMAIL_1>" in masked
    assert masked.startswith("📧 Contact me at ")
    assert masked.endswith(" 🎉 thanks! 🙏")


def test_multiple_emoji_sequences_do_not_shift_placeholder_position(engine):
    text = (
        "👨‍👩‍👧‍👦 Family contact: "
        "jane.smith@client.org for questions."
    )

    masked, entities = engine.redact(text)

    assert "jane.smith@client.org" not in masked
    assert "<EMAIL_1>" in masked
    assert masked.startswith("👨‍👩‍👧‍👦 Family contact: ")
    assert masked.endswith(" for questions.")


# ---------- Accented characters ----------

def test_accented_characters_adjacent_to_pii_are_preserved(engine):
    text = "Contactez résumé@company.com dès que possible, s'il vous plaît."

    masked, entities = engine.redact(text)

    assert "résumé@company.com" not in masked
    assert "<EMAIL_1>" in masked
    assert "Contactez " in masked
    assert "dès que possible, s'il vous plaît." in masked


def test_accented_characters_with_ascii_email(engine):
    text = "Café owner's email is cafe.owner@company.com for orders."

    masked, entities = engine.redact(text)

    assert "cafe.owner@company.com" not in masked
    assert "<EMAIL_1>" in masked
    assert masked.startswith("Café owner's email is ")
    assert masked.endswith(" for orders.")


# ---------- Placeholder consistency ----------

def test_placeholder_numbering_across_unicode_boundaries(engine):
    text = (
        "मेरा ईमेल john@acme.com है। 📧 फिर से, john@acme.com ही सही है। "
        "दूसरा jane@acme.com भी है।"
    )

    masked, entities = engine.redact(text)

    assert masked.count("<EMAIL_1>") == 2
    assert masked.count("<EMAIL_2>") == 1


# ---------- Pre-filter behavior ----------

def test_prefilter_does_not_skip_pii_in_non_latin_text():
    from dlp.pre_filter import might_contain_pii

    text = "मेरा ईमेल john@acme.com है।"

    assert might_contain_pii(text) is True


def test_prefilter_skips_clean_non_latin_text():
    from dlp.pre_filter import might_contain_pii

    text = "आज मौसम बहुत अच्छा है।"

    assert might_contain_pii(text) is False

def test_analyzer_failure_does_not_return_unmasked_text(engine, monkeypatch):
    """Analyzer failures must propagate rather than return raw input."""

    def simulate_analyzer_failure(*args, **kwargs):
        raise RuntimeError("Simulated analyzer failure")

    monkeypatch.setattr(
        engine.analyzer,
        "analyze",
        simulate_analyzer_failure,
    )

    text = "Contact me at security@example.com"

    with pytest.raises(RuntimeError, match="Simulated analyzer failure"):
        engine.redact(text)

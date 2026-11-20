import pytest

from dlp.vault import Vault
from dlp.stream_unmasker import StreamUnmasker


@pytest.fixture
def vault():
    instance = Vault()
    instance.store("session_1", {
        "<EMAIL_1>": "john@example.com",
        "<PHONE_1>": "+919876543210",
    })
    return instance


@pytest.fixture
def stream(vault):
    return StreamUnmasker(vault, "session_1")


def test_unmask_single_placeholder(stream):
    assert stream.feed("Contact <EMAIL_1>") == (
        "Contact john@example.com"
    )


def test_placeholder_split_across_two_chunks(stream):
    assert stream.feed("Contact <EMA") == "Contact "
    assert stream.feed("IL_1>") == "john@example.com"


def test_placeholder_split_across_multiple_chunks(stream):
    assert stream.feed("Contact <EM") == "Contact "
    assert stream.feed("AIL") == ""
    assert stream.feed("_1") == ""
    assert stream.feed(">") == "john@example.com"


def test_multiple_placeholders_in_stream(stream):
    result = stream.feed(
        "Email <EMAIL_1> or call <PHONE_1>"
    )

    assert result == (
        "Email john@example.com or call +919876543210"
    )


def test_multiple_placeholders_split_across_chunks(stream):
    assert stream.feed("Email <EMAIL_1> and <PHONE_") == (
        "Email john@example.com and "
    )

    assert stream.feed("1>") == "+919876543210"


def test_repeated_placeholder(stream):
    result = stream.feed(
        "<EMAIL_1> and again <EMAIL_1>"
    )

    assert result == (
        "john@example.com and again john@example.com"
    )


def test_unknown_placeholder_remains_unchanged(stream):
    assert stream.feed("<UNKNOWN_1>") == "<UNKNOWN_1>"


def test_ordinary_text_is_released_immediately(stream):
    assert stream.feed("Hello, world!") == "Hello, world!"


def test_empty_chunk_does_not_corrupt_buffer(stream):
    assert stream.feed("Contact <EMA") == "Contact "
    assert stream.feed("") == ""
    assert stream.feed("IL_1>") == "john@example.com"


def test_incomplete_tag_is_buffered_until_completion(stream):
    assert stream.feed("Hello <EMAIL_") == "Hello "
    assert stream.feed("1") == ""
    assert stream.feed(">") == "john@example.com"


def test_flush_releases_remaining_incomplete_text(stream):
    assert stream.feed("Hello <EMAIL_") == "Hello "
    assert stream.flush() == "<EMAIL_"


def test_flush_releases_remaining_complete_text(stream):
    assert stream.feed("Hello <EMAIL_1") == "Hello "
    assert stream.flush() == "<EMAIL_1"


def test_flush_with_empty_buffer_returns_empty_string(stream):
    assert stream.feed("Hello") == "Hello"
    assert stream.flush() == ""


def test_double_flush_raises_runtime_error(stream):
    stream.flush()

    with pytest.raises(RuntimeError, match="flush"):
        stream.flush()


def test_feed_after_flush_raises_runtime_error(stream):
    stream.flush()

    with pytest.raises(RuntimeError, match="flush"):
        stream.feed("Hello")


def test_non_string_chunk_raises_type_error(stream):
    with pytest.raises(TypeError, match="string"):
        stream.feed(123)


def test_session_isolation(vault):
    vault.store("session_2", {
        "<EMAIL_1>": "jane@example.com"
    })

    stream_a = StreamUnmasker(vault, "session_1")
    stream_b = StreamUnmasker(vault, "session_2")

    assert stream_a.feed("<EMAIL_1>") == "john@example.com"
    assert stream_b.feed("<EMAIL_1>") == "jane@example.com"


def test_incomplete_ordinary_angle_bracket_text(stream):
    assert stream.feed("Value <10") == "Value <10"
    assert stream.feed(" and more") == " and more"


def test_complete_non_placeholder_tag_is_preserved(stream):
    assert stream.feed("HTML <div> content") == (
        "HTML <div> content"
    )


def test_ordinary_angle_bracket_text_is_released_immediately(stream):
    assert stream.feed("Price is <10 and available") == (
        "Price is <10 and available"
    )


def test_html_like_tag_is_released_unchanged(stream):
    assert stream.feed("Hello <div> world") == (
        "Hello <div> world"
    )

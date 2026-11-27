import json
import pytest

from dlp.vault import Vault
from dlp.redis_vault import RedisVault
from dlp.interceptor import DLPInterceptor
from dlp.stream_unmasker import StreamUnmasker


SESSION_ID = "day19-json-session"

MAPPING = {
    "<EMAIL_1>": 'alice@example.com',
    "<PERSON_1>": 'Alice "The Analyst"',
    "<SECRET_1>": 'line1\\line2\nline3',
}


@pytest.fixture
def vault():
    instance = Vault()
    instance.store(SESSION_ID, MAPPING)
    return instance


@pytest.fixture
def redis_vault():
    instance = RedisVault(
        host="127.0.0.1",
        port=6380,
        db=14,
        ttl_seconds=60,
    )

    instance.clear_session(SESSION_ID)
    instance.store(SESSION_ID, MAPPING)

    yield instance

    instance.clear_session(SESSION_ID)


@pytest.fixture
def json_text():
    return json.dumps({
        "email": "<EMAIL_1>",
        "profile": {
            "name": "<PERSON_1>",
            "active": True,
        },
        "messages": [
            "Contact <EMAIL_1>",
            "Sensitive value: <SECRET_1>",
        ],
    })


def test_vault_unmask_json_preserves_json_structure(vault, json_text):
    result = vault.unmask_json(json_text, SESSION_ID)
    restored = json.loads(result)

    assert restored == {
        "email": MAPPING["<EMAIL_1>"],
        "profile": {
            "name": MAPPING["<PERSON_1>"],
            "active": True,
        },
        "messages": [
            "Contact " + MAPPING["<EMAIL_1>"],
            "Sensitive value: " + MAPPING["<SECRET_1>"],
        ],
    }


def test_vault_unmask_json_handles_arrays(vault):
    masked = json.dumps(["<EMAIL_1>", "<PERSON_1>"])

    result = vault.unmask_json(masked, SESSION_ID)

    assert json.loads(result) == [
        MAPPING["<EMAIL_1>"],
        MAPPING["<PERSON_1>"],
    ]


def test_vault_unmask_json_handles_quotes_backslashes_and_newlines(vault):
    masked = json.dumps({"secret": "<SECRET_1>"})

    result = vault.unmask_json(masked, SESSION_ID)

    assert json.loads(result)["secret"] == MAPPING["<SECRET_1>"]


def test_vault_unmask_json_preserves_unknown_placeholders(vault):
    masked = json.dumps({"unknown": "<UNKNOWN_1>"})

    result = vault.unmask_json(masked, SESSION_ID)

    assert json.loads(result)["unknown"] == "<UNKNOWN_1>"


def test_vault_unmask_json_rejects_invalid_json(vault):
    with pytest.raises(ValueError):
        vault.unmask_json('{"email": "<EMAIL_1>"', SESSION_ID)


def test_plain_unmask_text_remains_unchanged(vault):
    result = vault.unmask_text(
        "Contact <EMAIL_1>",
        SESSION_ID,
    )

    assert result == "Contact " + MAPPING["<EMAIL_1>"]


def test_redis_vault_unmask_json(redis_vault):
    masked = json.dumps({
        "email": "<EMAIL_1>",
        "secret": "<SECRET_1>",
    })

    result = redis_vault.unmask_json(masked, SESSION_ID)

    assert json.loads(result) == {
        "email": MAPPING["<EMAIL_1>"],
        "secret": MAPPING["<SECRET_1>"],
    }


def test_interceptor_unmask_json(vault):
    interceptor = DLPInterceptor(vault=vault)

    masked = json.dumps({"email": "<EMAIL_1>"})

    result = interceptor.unmask_json(masked, SESSION_ID)

    assert json.loads(result) == {
        "email": MAPPING["<EMAIL_1>"],
    }


def test_stream_unmasker_json_mode(vault):
    stream = StreamUnmasker(
        vault,
        SESSION_ID,
        json_mode=True,
    )

    assert stream.feed('{"email": ') == ""
    assert stream.feed('"<EMAIL_1>"') == ""
    assert stream.feed('}') == ""

    result = stream.flush()

    assert json.loads(result) == {
        "email": MAPPING["<EMAIL_1>"],
    }


def test_stream_unmasker_json_mode_handles_special_characters(vault):
    stream = StreamUnmasker(
        vault,
        SESSION_ID,
        json_mode=True,
    )

    masked = json.dumps({"secret": "<SECRET_1>"})

    assert stream.feed(masked[:10]) == ""
    assert stream.feed(masked[10:]) == ""

    result = stream.flush()

    assert json.loads(result)["secret"] == MAPPING["<SECRET_1>"]

def test_vault_unmask_json_rejects_non_standard_json(vault):
    with pytest.raises(ValueError):
        vault.unmask_json('{"value": NaN}', SESSION_ID)

    with pytest.raises(ValueError):
        vault.unmask_json('{"value": Infinity}', SESSION_ID)

def test_plain_unmask_text_does_not_escape_json_special_values(vault):
    """Documents the limitation of plain text unmasking.

    A literal quote in the original value can corrupt JSON when
    unmask_text() performs direct string substitution.
    """
    masked_response = json.dumps({"name": "<PERSON_1>"})

    result = vault.unmask_text(masked_response, SESSION_ID)

    with pytest.raises(json.JSONDecodeError):
        json.loads(result)

def test_redis_vault_unmask_json_rejects_non_standard_json(redis_vault):
    with pytest.raises(ValueError):
        redis_vault.unmask_json('{"value": NaN}', SESSION_ID)

    with pytest.raises(ValueError):
        redis_vault.unmask_json('{"value": Infinity}', SESSION_ID)

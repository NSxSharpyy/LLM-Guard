
"""Demonstrate Redis vault sharing across separate OS processes.

Usage:
    python scripts/distributed_retrieval_demo.py writer
    python scripts/distributed_retrieval_demo.py reader
"""

import sys

from dlp.redis_vault import RedisVault


SESSION_ID = "day9-distributed-demo"
MASKED_TEXT = "Contact <EMAIL_1> for further information."


def writer():
    """Store a mapping in Redis."""
    vault = RedisVault(db=15, ttl_seconds=900)

    if not vault.ping():
        raise RuntimeError("Redis is unavailable")

    vault.clear_session(SESSION_ID)

    vault.store(
        SESSION_ID,
        {
            "<EMAIL_1>": "john@example.com",
        },
    )

    print("WRITER PROCESS")
    print("Mapping stored successfully.")
    print("Session:", SESSION_ID)
    print("Masked text:", MASKED_TEXT)


def reader():
    """Retrieve and use the mapping from another process."""
    vault = RedisVault(db=15, ttl_seconds=900)

    if not vault.ping():
        raise RuntimeError("Redis is unavailable")

    mapping = vault.get_mapping(SESSION_ID)
    restored_text = vault.unmask_text(MASKED_TEXT, SESSION_ID)

    print("READER PROCESS")
    print("Retrieved mapping:", mapping)
    print("Restored text:", restored_text)

    if restored_text != "Contact john@example.com for further information.":
        raise RuntimeError("Cross-process retrieval failed")

    print("CROSS-PROCESS RETRIEVAL: PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"writer", "reader"}:
        print(
            "Usage: python scripts/distributed_retrieval_demo.py "
            "{writer|reader}"
        )
        sys.exit(1)

    if sys.argv[1] == "writer":
        writer()
    else:
        reader()

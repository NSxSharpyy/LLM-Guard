from dashboard.policy_catalog import (
    POLICY_CATALOG,
    get_policy,
    list_policies,
)


def test_policy_ids_are_unique():
    ids = [policy.policy_id for policy in list_policies()]
    assert len(ids) == len(set(ids))


def test_all_eight_implemented_controls_are_registered():
    assert len(POLICY_CATALOG) == 8


def test_policy_lookup():
    policy = get_policy("DLP-001-SECRET-EXFILTRATION")

    assert policy is not None
    assert policy.action == "BLOCK"
    assert policy.component == "Input DLP"


def test_unknown_policy_returns_none():
    assert get_policy("UNKNOWN-POLICY") is None


def test_registry_is_read_only_and_not_dynamically_configurable():
    assert all(policy.configurable is False for policy in POLICY_CATALOG)


def test_policy_source_files_exist():
    from pathlib import Path

    for policy in POLICY_CATALOG:
        assert Path(policy.source_file).is_file()

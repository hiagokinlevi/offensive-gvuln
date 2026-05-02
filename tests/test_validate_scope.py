from scripts.validate_scope import main, validate_entries


def test_validate_entries_non_strict_allows_wildcards():
    code, invalid, wildcards = validate_entries(["*.example.com"], strict=False)
    assert code == 0
    assert invalid == []
    assert wildcards == ["*.example.com"]


def test_validate_entries_strict_rejects_wildcards():
    code, invalid, wildcards = validate_entries(["*.example.com"], strict=True)
    assert code == 2
    assert invalid == []
    assert wildcards == ["*.example.com"]


def test_main_strict_exit_code_2_for_wildcards():
    code = main(["--strict", "*.example.com"])
    assert code == 2


def test_main_non_strict_exit_code_0_for_wildcards():
    code = main(["*.example.com"])
    assert code == 0

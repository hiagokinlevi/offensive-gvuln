from offensive_gvuln_cli import main


def test_preflight_transition_pass(capsys):
    rc = main(
        [
            "preflight-transition",
            "--finding-id",
            "F-100",
            "--current-state",
            "open",
            "--target-state",
            "in_progress",
        ]
    )

    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("PASS:")


def test_preflight_transition_fail(capsys):
    rc = main(
        [
            "preflight-transition",
            "--finding-id",
            "F-101",
            "--current-state",
            "closed",
            "--target-state",
            "open",
        ]
    )

    out = capsys.readouterr().out
    assert rc == 1
    assert out.startswith("FAIL:")

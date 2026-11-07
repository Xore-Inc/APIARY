#!/usr/bin/env python3
"""Regression test for #3664: ci-registry-mirror.service must come back up
when Docker restarts.

`Requires=docker.service` stops the mirror whenever Docker stops, and only a
WantedBy on docker.service starts it again. The installer renders the unit
and runs `systemctl enable --now`, so the WantedBy takes effect on re-run.
"""
from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "scripts/github-ci-runner/install-registry-mirror.sh"


def test_unit_is_wanted_by_docker_so_a_docker_start_restarts_the_mirror():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "Requires=docker.service" in text
    assert "WantedBy=multi-user.target docker.service" in text, (
        "the rendered [Install] section must include docker.service (#3664)"
    )


def test_installer_enables_the_unit_so_the_new_wantedby_takes_effect():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "systemctl enable --now ci-registry-mirror.service" in text

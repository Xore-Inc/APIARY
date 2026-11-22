# Vendored: CAPEv2's `agent.py`

`agent.py` in this directory is vendored verbatim from
[kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2), commit
`9dbe3356e5947399d4f1b8eee9ad8ed5ef9f4509` (2026-08-07).

Why vendored rather than fetched at build time: this repo's own convention
(`docs/sandbox/windows`'s golden image bakes in fixed local copies of
everything it needs) is to
pin external components as an explicit file in the repo rather than a
build-time `curl`/`git clone` against a moving upstream ref, so a rebuild
six months from now installs the exact agent this was tested against, not
whatever `master` happens to be that day.

Per CAPEv2's own docs
(`docs/book/src/installation/guest/agent.rst`, read directly off the real
upstream checkout on the homeserver rather than assumed): this file is
copied into the guest, run as `agent.pyw` (renamed to suppress the console
window CAPE's own `human.py` auxiliary module would otherwise interfere
with) via a `AtLogOn`/`RunLevel Highest` scheduled task — see
`sandbox/cape/packer/scripts/02-cape-agent.ps1`, which installs and wires
it up during `win11-cape.pkr.hcl`'s build.

**No automated sync check yet** (unlike the theme/noVNC vendoring, which
have one) — this file changes rarely enough upstream that a manual re-vendor
when a real reason comes up (a protocol change breaking `cape-worker.py`'s
`apiv2` client, a security fix) is enough for now. Add a CI check here too
if that assumption stops holding.

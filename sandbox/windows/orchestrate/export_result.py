#!/usr/bin/env python3
"""Build the dashboard-compatible windows-{job}.json from a completed run.

#53's smoke test found the actual, previously-unknown gap in this pipeline:
every artifact-collection step works (registry snapshots, autoruns/services
diffs, Sysmon/PowerShell EVTX, IOC extraction, memory dump, report.html) but
nothing ever wrote a file matching dashboard/sandbox.go's `sandboxResult`
struct -- the one thing the dashboard actually reads to show anything on
/sandbox at all. A fully successful detonation was completely invisible to
the dashboard. This is the writer for that file, modeled directly on
sandbox/export-result.py (the Linux runner's equivalent, already proven
against the same Go struct) rather than designed from scratch.

Known gaps, deliberately not solved here (see #53's PR/issue thread):
  - No PE-forensics step exists in this pipeline (unlike the Linux runner's
    pe-forensics.json), so windows_forensics.detected stays False. Sections,
    imports, imphash, etc. are all unavailable until that's added.
  - #510 wired up host-side pcap capture (run_dir/network.pcap,
    zeek_logs/, suricata_alerts.json -- generate_report.py already reads
    all three), but this exporter's network_summary still doesn't: it is
    still built from Sysmon's own DNS/connection events (already parsed by
    extract_iocs.py) rather than the packet-level record now available
    alongside it. Left as-is here since #510's own scope was making the
    capture exist at all, not consuming it from every downstream reader.
  - ioc_extracted.json's DNS/IP data includes this image's own decoy traffic
    (the living-persona daemon and traffic-noise generator, #290/#291 --
    e.g. *.acp-persona.net) alongside anything the sample actually did.
    Nothing here filters that out, so risk scoring below is a floor, not a
    verified signal -- a real fix needs the noise generator's own tagging
    (X-Persona-Noise header / MCGPersona UA, per tools/filter-pcap.sh) wired
    into this extraction, not just pcaps.
"""

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

MAX_TEXT = 32768
# #2775: failure_reason carries str(e) for a failed legacy-WinRM run. One
# sentence of cause is the point; a full argv dump is not.
MAX_FAILURE_REASON = 512
MAX_LINES = 200
# #480: dashboard/sandbox.go serves *.diagnostics.zip up to 16MiB
# (serveSandboxExport's maxSize for artifactKind=="diagnostics") -- these
# stay comfortably under that rather than sitting at the platform ceiling.
MAX_BUNDLE_FILE = 2 * 1024 * 1024
MAX_BUNDLE_TOTAL = 15 * 1024 * 1024
# #480: the full registry export/diff/autoruns/services artifacts have
# never been downloadable through the dashboard at all -- only the 200-line
# changed_files summary reached the JSON. sandbox/export-result.py's
# Linux-side write_diagnostics_bundle() already solves exactly this for the
# Linux sandbox (dashboard/sandbox.go's *.diagnostics.zip serving is
# backend-agnostic, keyed only on the file's existence); this mirrors it.
BUNDLE_FILES = (
    'reg_hklm_before.reg', 'reg_hklm_after.reg',
    'reg_hkcu_before.reg', 'reg_hkcu_after.reg',
    'regshot_diff.txt', 'autoruns_before.csv', 'autoruns_after.csv',
    'autoruns_diff.txt', 'services_before.csv', 'services_after.csv',
    'services_diff.txt', 'orchestrator.log',
)


def write_diagnostics_bundle(out_dir: Path, output: Path):
    total = 0
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in BUNDLE_FILES:
            path = out_dir / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                data = path.read_bytes()[:MAX_BUNDLE_FILE]
            except OSError:
                continue
            if total + len(data) > MAX_BUNDLE_TOTAL:
                break
            archive.writestr(name, data)
            total += len(data)
    output.chmod(0o640)


def text(path: Path, limit=MAX_TEXT, encoding='utf-8'):
    try:
        return path.read_bytes()[:limit].decode(encoding, 'replace')
    except OSError:
        return ''


def lines(path: Path, limit=MAX_LINES, encoding='utf-8'):
    return text(path, 131072, encoding).splitlines()[:limit]


# PowerShell's Out-File/redirection default encoding is UTF-16LE with a BOM
# -- autoruns_diff.txt and services_diff.txt are both produced that way
# (Compare-Object | Out-File in run_sample.py). Reading them as UTF-8
# produces the interleaved-null-byte garbage this decodes correctly instead.
def ps_text(path: Path, limit=MAX_TEXT):
    return text(path, limit, encoding='utf-16')


def ps_lines(path: Path, limit=MAX_LINES):
    return lines(path, limit, encoding='utf-16')


def build_result(out_dir: Path) -> dict:
    meta = {}
    meta_path = out_dir / 'metadata.json'
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    sha256 = meta.get('sha256', out_dir.name)
    detonated_at = meta.get('detonated_at', '')
    completed_at = datetime.now(timezone.utc).isoformat()
    try:
        started = datetime.fromisoformat(detonated_at) if detonated_at else None
        completed = datetime.fromisoformat(completed_at)
        duration = max(0, round((completed - started).total_seconds(), 3)) if started else 0
    except ValueError:
        duration = 0

    ioc_summary = {}
    ioc_path = out_dir / 'ioc_extracted.json'
    if ioc_path.exists():
        try:
            ioc_summary = json.loads(ioc_path.read_text()).get('summary', {})
        except (json.JSONDecodeError, OSError):
            pass
    remote_ips = ioc_summary.get('unique_remote_ips', [])
    dns_domains = ioc_summary.get('unique_dns_domains', [])
    download_urls = ioc_summary.get('unique_download_urls', [])
    download_cradles = ioc_summary.get('ps_download_cradles', [])
    # #482: static (binary-embedded) IOCs and the static-only ("dormant",
    # never triggered by this run's observation window) subset. Previously
    # remote_ips/download_urls/download_cradles above were computed only to
    # feed techniques/risk_score below and then discarded -- neither they
    # nor these new static fields were ever placed in the exported result,
    # so nothing downstream (dashboard, ES) could see them at all.
    static_remote_ips = ioc_summary.get('static_remote_ips', [])
    static_dns_domains = ioc_summary.get('static_dns_domains', [])
    static_download_urls = ioc_summary.get('static_download_urls', [])
    static_unc_paths = ioc_summary.get('static_unc_paths', [])
    static_only_remote_ips = ioc_summary.get('static_only_remote_ips', [])
    static_only_dns_domains = ioc_summary.get('static_only_dns_domains', [])
    static_only_download_urls = ioc_summary.get('static_only_download_urls', [])

    autoruns_diff = ps_lines(out_dir / 'autoruns_diff.txt')
    services_diff = ps_lines(out_dir / 'services_diff.txt')
    regshot_diff = lines(out_dir / 'regshot_diff.txt', 500)
    # #480: regshot_diff.txt is now a host-side Python difflib.unified_diff()
    # of this run's single "after" export against the cached golden-image
    # baseline (run_sample.py's diff_registry_against_baseline()), not
    # fc.exe's line-numbered dump against an in-guest "before" export --
    # the in-guest "before" step was removed entirely (#480 also killed one
    # of the two ~8.5-minute reg.exe exports every run used to pay for).
    # Unified diff's own convention: '+'/'-' prefixed lines are the actual
    # additions/removals, '+++'/'---' are the fromfile/tofile headers this
    # excludes explicitly rather than matching '^[+-]' too loosely.
    regshot_changed = [
        ln for ln in regshot_diff
        if ln.startswith(('+', '-')) and not ln.startswith(('+++', '---'))
    ]

    techniques = []
    technique_ids = set()

    def technique(identifier, name, evidence):
        if identifier not in technique_ids:
            technique_ids.add(identifier)
            techniques.append({'id': identifier, 'name': name, 'evidence': evidence[:256]})

    if any('added' in ln.lower() or '<' in ln or '>' in ln for ln in autoruns_diff):
        technique('T1547', 'Boot or Logon Autostart Execution', 'autoruns diff shows a change')
    if any('added' in ln.lower() or '<' in ln or '>' in ln for ln in services_diff):
        technique('T1543.003', 'Windows Service', 'service list diff shows a change')
    if remote_ips and dns_domains:
        technique('T1071.004', 'DNS', 'DNS query accompanied by a network connection to a remote IP')
    if download_urls or download_cradles:
        technique('T1105', 'Ingress Tool Transfer', 'download URL or PowerShell download cradle observed')
    if download_cradles:
        technique('T1059.001', 'PowerShell', 'PowerShell ScriptBlock log shows a download cradle pattern')
    if len(regshot_changed) > 20:
        technique('T1112', 'Modify Registry', f'{len(regshot_changed)} registry lines changed')

    # Additive, capped risk score -- same shape as export-result.py's, with
    # Windows-appropriate signals substituted for the Linux syscall-based
    # ones. Deliberately conservative given the decoy-traffic caveat above:
    # DNS/IP presence alone (T1071.004) is NOT scored on its own, since this
    # image's own persona/noise traffic guarantees it fires on every run.
    risk_score = 5
    risk_score += min(20, len(regshot_changed) // 10)
    risk_score += 25 if any(t['id'] in ('T1547', 'T1543.003') for t in techniques) else 0
    risk_score += 20 if download_cradles else 0
    risk_score += 10 if download_urls else 0
    risk_score = min(100, risk_score)
    risk_level = ('critical' if risk_score >= 75 else 'high' if risk_score >= 50
                  else 'medium' if risk_score >= 25 else 'low')

    procmon_missing = not (out_dir / 'procmon.csv').exists()

    stamp = detonated_at.replace('-', '').replace(':', '').split('.')[0].replace('T', 'T') if detonated_at else \
        datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    job = f'windows-{stamp}-{sha256[:12]}'

    # #490: the in-guest orchestration path calls post_process() (and
    # therefore this) even on a watchdog force-kill -- deliberately, to
    # salvage whatever partial artifacts virt-copy-out could still pull off
    # the guest, rather than the old assumption here that reaching this
    # function at all meant success (true only for the pre-#490 WinRM path,
    # where a failed run raised before ever getting here). Map
    # detonate_inguest()'s own metadata.json run_status onto the vocabulary
    # the dashboard already understands -- run_status == "failed" or a
    # non-empty timeout_reason both mark the run incomplete, which is what
    # actually drives Workbench's pass/fail decision.
    #
    # #2775 review: this comment used to name dashboard/sandbox.go's
    # normalizeSandboxResult() and workbench_orchestrator.go's
    # reconcileWorkbenchRun. The Go dashboard is gone and neither file exists;
    # the live consumers are backend-service/src/workbench_orchestrator.rs
    # (run_status == "failed" -> incomplete, and child.reason taken from
    # failure_reason, falling back to timeout_reason) and the dashboard
    # (Xore-Inc/apiary-dashboard), which shows failure_reason for an
    # incomplete run.
    watchdog_timeout = meta.get('run_status') == 'watchdog_timeout'
    # #2775: detonate_legacy_winrm() now stamps this the same way
    # detonate_inguest() always has -- 'legacy_winrm_failed' on any
    # exception raised before it reached its own success path, 'completed'
    # otherwise. Previously meta.get('run_status') was only ever
    # 'watchdog_timeout' or absent (the legacy path set nothing), so this
    # was a two-way branch; it is a three-way one now, and any *other*
    # legacy failure that isn't the watchdog case must still map to
    # Incomplete rather than fall through to the 'completed' default.
    legacy_winrm_failed = meta.get('run_status') == 'legacy_winrm_failed'
    run_status = 'failed' if (watchdog_timeout or legacy_winrm_failed) else 'completed'
    timeout_reason = (
        'watchdog timeout: guest did not self-shutdown within the deadline (#490)'
        if watchdog_timeout else ''
    )
    # Capped like every other free-text field here (evidence[:256],
    # changed_files[:200], MAX_TEXT): this carries str(e) from an arbitrary
    # exception, and a CalledProcessError's repr includes the whole argv.
    # It is rendered verbatim in the dashboard's job view.
    failure_reason = (meta.get('run_status_detail', '')[:MAX_FAILURE_REASON]
                      if legacy_winrm_failed else '')

    return {
        'version': 2,
        'job': job,
        'sha256': sha256,
        'capture_name': meta.get('filename', sha256),
        'source': '',
        'requested_at': detonated_at,
        'started_at': detonated_at,
        'completed_at': completed_at,
        'duration_seconds': duration,
        'exit_status': '0',
        'run_status': run_status,
        'guest_started': True,
        'failure_reason': failure_reason,
        'timeout_reason': timeout_reason,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'network': 'isolated',
        'route': 'windows',
        'file_type': 'PE',
        'platform': 'Windows',
        'analysis_path': 'dynamic',
        'execution_mode': 'native',
        'classification': {
            'code': 'pe',
            'label': 'Windows executable',
            'platform': 'Windows',
            'category': 'executable',
            'analysis_path': 'dynamic',
            'dynamic': True,
        },
        'hashes': {'md5': '', 'sha1': '', 'sha256': sha256},
        'stdout': '',
        'stderr': '',
        'runner_log': '',
        'changed_files': regshot_changed[:200],
        'sockets_before': [],
        'sockets_after': [],
        'top_syscalls': [],
        'network_summary': {
            'packets': 0,
            'bytes': 0,
            'protocols': {},
            'events': [],
            'attempts': [],
            'guest_packets': 0,
            'guest_pcap_bytes': 0,
            'guest_protocols': {},
            'guest_events': [],
            'dns_queries': dns_domains[:500],
            'dns_events': [],
            'remote_ips': remote_ips[:500],
        },
        # #482: dynamic download IOCs (previously computed, never exported)
        # alongside static (binary-embedded) IOCs and the static-only
        # ("dormant") subset -- present in this sample but never observed
        # at runtime, either because nothing in this run's window triggered
        # the code path that uses it, or because it never would (a backup
        # C2 domain, an alternate exfil share).
        'iocs': {
            'download_urls': download_urls[:500],
            'download_cradle_count': len(download_cradles),
            'static_remote_ips': static_remote_ips[:500],
            'static_dns_domains': static_dns_domains[:500],
            'static_download_urls': static_download_urls[:500],
            'static_unc_paths': static_unc_paths[:500],
            'static_only_remote_ips': static_only_remote_ips[:500],
            'static_only_dns_domains': static_only_dns_domains[:500],
            'static_only_download_urls': static_only_download_urls[:500],
        },
        # No PE-forensics step in this pipeline yet -- see module docstring.
        'windows_forensics': {'detected': False},
        'artifacts': {
            'kernel': '', 'exiftool': '', 'pe_objdump': '',
            'processes_before': [], 'processes_after': [],
            'host_tcpdump_log': '', 'guest_tcpdump_log': '',
            'classification_error': '', 'pe_forensics_error': '',
            'console_log': '', 'qemu_log': '',
            'domain_state': 'reverted to golden image',
            'qemu_status': '',
            'host_phase': ('completed (procmon.csv missing -- export failed or timed out, #502)'
                            if procmon_missing else 'completed'),
        },
        'techniques': techniques,
        'truncated': True,
    }


def write_result(out_dir: Path, results_dir: Path) -> Path:
    payload = build_result(out_dir)
    output = results_dir / f'{payload["job"]}.json'
    results_dir.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    output.chmod(0o640)
    try:
        write_diagnostics_bundle(out_dir, results_dir / f'{payload["job"]}.diagnostics.zip')
    except OSError:
        pass  # best-effort -- the JSON result above is what matters
    return output


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('Usage: export_result.py <out_dir> <results_dir>')
        sys.exit(1)
    path = write_result(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f'wrote {path}')

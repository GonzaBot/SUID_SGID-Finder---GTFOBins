#!/usr/bin/env python3
"""
SecurAudit: local SUID/SGID auditor with GTFOBins hints.
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import stat
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


GTFOBINS = {
    "bash": ("Critical", "GTFOBins match: can spawn a privileged shell when SUID is enabled."),
    "cp": ("High", "GTFOBins match: can copy or overwrite protected files."),
    "env": ("Critical", "GTFOBins match: can execute commands while keeping elevated privileges."),
    "find": ("Critical", "GTFOBins match: can execute commands through -exec."),
    "less": ("High", "GTFOBins match: can escape to a shell from the pager."),
    "more": ("High", "GTFOBins match: can escape to a shell from the pager."),
    "nano": ("High", "GTFOBins match: can read or modify protected files."),
    "nmap": ("High", "GTFOBins match: old interactive mode can execute commands."),
    "perl": ("Critical", "GTFOBins match: can execute arbitrary code."),
    "python": ("Critical", "GTFOBins match: can execute arbitrary code."),
    "python2": ("Critical", "GTFOBins match: can execute arbitrary code."),
    "python3": ("Critical", "GTFOBins match: can execute arbitrary code."),
    "ruby": ("Critical", "GTFOBins match: can execute arbitrary code."),
    "sh": ("Critical", "GTFOBins match: can spawn a privileged shell when SUID is enabled."),
    "tar": ("High", "GTFOBins match: can execute commands through checkpoint actions."),
    "vim": ("High", "GTFOBins match: can edit protected files or spawn a shell."),
    "vi": ("High", "GTFOBins match: can edit protected files or spawn a shell."),
    "wget": ("High", "GTFOBins match: can download or overwrite files in privileged contexts."),
}

SEVERITY_LABELS = {
    "Critical": "Critical",
    "High": "High",
    "Review": "Review",
    "Info": "Info",
}

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Review": 2,
    "Info": 3,
}

STANDARD_SYSTEM_DIRS = {
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
}

EXPECTED_SPECIAL_BINARIES = {
    "VirtualBoxVM",
    "chage",
    "chfn",
    "chsh",
    "crontab",
    "expiry",
    "fusermount",
    "fusermount3",
    "gpasswd",
    "locate",
    "mount",
    "newgrp",
    "passwd",
    "pkexec",
    "plocate",
    "sg",
    "ssh-agent",
    "su",
    "sudo",
    "sudoedit",
    "umount",
    "virtualboxvm",
}

FAIL_SEVERITIES = {"Critical", "High", "Review"}


@dataclass(frozen=True)
class Finding:
    path: Path
    mode: str
    owner_uid: int
    group_gid: int
    severity: str
    note: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find SUID/SGID binaries and highlight known GTFOBins risks."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["/"],
        help="Directories to scan. Defaults to '/'.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show every SUID/SGID file, not only GTFOBins matches.",
    )
    parser.add_argument(
        "--no-skip-virtual",
        action="store_true",
        help="Also scan virtual filesystems such as /proc, /sys, /dev, and /run.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with status 1 when risky findings are detected.",
    )
    return parser.parse_args()


def file_mode(mode: int) -> str:
    flags = []
    if mode & stat.S_ISUID:
        flags.append("SUID")
    if mode & stat.S_ISGID:
        flags.append("SGID")
    return "+".join(flags)


def is_expected_system_binary(path: Path, owner_uid: int) -> bool:
    return (
        path.parent.as_posix() in STANDARD_SYSTEM_DIRS
        and path.name in EXPECTED_SPECIAL_BINARIES
        and owner_uid == 0
    )


def gtfobins_risk_for(path: Path, mode: str, owner_uid: int) -> tuple[str, str]:
    base_severity, base_note = GTFOBINS[path.name]
    current_uid = os.getuid()

    if "SUID" in mode and owner_uid == 0:
        return base_severity, base_note
    if "SUID" in mode and owner_uid == current_uid:
        return (
            "Review",
            "GTFOBins match, but SUID owner is the current user; this is not root escalation by itself.",
        )
    if "SUID" in mode:
        return (
            "High",
            "GTFOBins match with SUID owned by another user; this can cross a privilege boundary.",
        )
    return (
        "Review",
        "GTFOBins match with SGID only; review group ownership and whether this is expected.",
    )


def risk_for(path: Path, mode: str, owner_uid: int) -> tuple[str, str]:
    name = path.name
    if name in GTFOBINS:
        return gtfobins_risk_for(path, mode, owner_uid)
    if is_expected_system_binary(path, owner_uid):
        return "Info", "Common system binary with expected special permissions; verify package integrity if unsure."
    return "Review", "Special permission is enabled but this file is not in the expected-system list."


def should_skip_dir(path: Path, skip_virtual: bool) -> bool:
    if not skip_virtual:
        return False
    return path.as_posix() in {"/dev", "/proc", "/run", "/sys"}


def scan_path(root: Path, show_all: bool, skip_virtual: bool) -> list[Finding]:
    findings: list[Finding] = []

    if not root.exists():
        print(f"[WARN] Path does not exist: {root}", file=sys.stderr)
        return findings

    for current_root, dirnames, filenames in os.walk(root, topdown=True, onerror=None):
        current_path = Path(current_root)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if not should_skip_dir(current_path / dirname, skip_virtual)
        ]

        for filename in filenames:
            path = current_path / filename
            try:
                info = path.lstat()
            except (FileNotFoundError, PermissionError, OSError):
                continue

            if not stat.S_ISREG(info.st_mode):
                continue

            has_special_bit = info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            if not has_special_bit:
                continue

            mode = file_mode(info.st_mode)
            severity, note = risk_for(path, mode, info.st_uid)
            if severity in {"Info", "Review"} and not show_all:
                continue

            findings.append(
                Finding(
                    path=path,
                    mode=mode,
                    owner_uid=info.st_uid,
                    group_gid=info.st_gid,
                    severity=severity,
                    note=note,
                )
            )

    return findings


def user_label(uid: int) -> str:
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = "unknown"
    return f"{name} (uid {uid})"


def group_label(gid: int) -> str:
    try:
        name = grp.getgrgid(gid).gr_name
    except KeyError:
        name = "unknown"
    return f"{name} (gid {gid})"


def explain_mode(mode: str) -> str:
    if mode == "SUID":
        return "runs with the file owner's privileges"
    if mode == "SGID":
        return "runs with the file group's privileges"
    if mode == "SUID+SGID":
        return "runs with the file owner's and group's privileges"
    return "special permission is enabled"


def print_summary(findings: list[Finding]) -> None:
    counts = Counter(finding.severity for finding in findings)
    parts = [
        f"{SEVERITY_LABELS[severity]}: {counts[severity]}"
        for severity in ("Critical", "High", "Review", "Info")
        if counts[severity]
    ]
    print(f"Summary: {len(findings)} finding(s)" + (f" ({', '.join(parts)})" if parts else ""))


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No risky SUID/SGID GTFOBins matches found.")
        print("Tip: use --all to also show expected and review-only special permissions.")
        return

    findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], str(item.path)))

    print_summary(findings)
    print()
    print("Quick legend:")
    print("  SUID: the program runs with the file owner's privileges.")
    print("  SGID: the program runs with the file group's privileges.")
    print("  Info: common system binary; usually expected, not a vulnerability by itself.")
    print("  Review: special permission found on an unclassified file.")
    print()

    for index, finding in enumerate(findings, start=1):
        severity = SEVERITY_LABELS[finding.severity]
        print(f"[{index}] {finding.path}")
        print(f"    Level     : {severity}")
        print(f"    Permission: {finding.mode} ({explain_mode(finding.mode)})")
        print(f"    Owner     : {user_label(finding.owner_uid)}")
        print(f"    Group     : {group_label(finding.group_gid)}")
        print(f"    Reason    : {finding.note}")
        print()

    print("Next step:")
    print("  Prioritize Critical/High findings. Info entries are usually normal system")
    print("  permissions; Review entries deserve manual validation.")


def main() -> int:
    args = parse_args()
    skip_virtual = not args.no_skip_virtual
    findings: list[Finding] = []

    for raw_path in args.paths:
        print(f"Scanning {raw_path} ...", file=sys.stderr, flush=True)
        findings.extend(scan_path(Path(raw_path), args.all, skip_virtual))

    print_findings(findings)
    print(f"Total shown: {len(findings)} finding(s)")
    has_failing_findings = any(finding.severity in FAIL_SEVERITIES for finding in findings)
    return 1 if has_failing_findings and args.fail_on_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

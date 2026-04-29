# SecurAudit: SUID/SGID Configuration Auditor

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)

**SecurAudit** is an enterprise-grade, lightweight local security assessment tool designed to identify misconfigured SUID and SGID binaries on Unix/Linux systems. It goes beyond simple discovery by cross-referencing findings with a built-in dataset based on the renowned **GTFOBins** project. 

This automatic cross-referencing immediately alerts system administrators and security engineers to potential Privilege Escalation vectors, providing proof-of-concept indicators and actionable mitigation strategies.

## Features

* **Rapid Local Scanning:** Utilizes native Python `os.walk` and `stat` for fast, dependency-light filesystem traversal.
* **Automated Threat Intelligence:** Cross-references discovered SUID/SGID binaries against an internal GTFOBins threat database.
* **Actionable Reporting:** Generates readable terminal output categorizing findings as Info, Review, High, or Critical.
* **Enterprise Ready:** Clear output formats designed to be read by IT compliance and security operations teams.

## Requirements

* Linux, macOS, or WSL.
* Python 3.8 or newer.
* Permission to read the directories you want to scan.

You do not need to install third-party Python packages.

## Installation

The project has no third-party Python dependencies. The setup script creates a
virtual environment and marks the auditor as executable.

```bash
cd "SUID_SGID Finder + GTFOBins"
chmod +x setup.sh
./setup.sh
```

If you do not want to use the setup script, you can run it directly:

```bash
chmod +x suid_auditor.py
./suid_auditor.py --help
```

## Usage

### 1. First safe test

Start by scanning a small system directory. This is faster and easier to read:

```bash
./suid_auditor.py /usr/bin
```

If nothing risky is found, you will see:

```text
No risky SUID/SGID GTFOBins matches found.
```

If something risky is found, you will see output like this:

```text
Summary: 1 finding(s) (Critical: 1)

Quick legend:
  SUID: the program runs with the file owner's privileges.
  SGID: the program runs with the file group's privileges.
  Info: common system binary; usually expected, not a vulnerability by itself.
  Review: special permission found on an unclassified file.

[1] /usr/bin/sh
    Level     : Critical
    Permission: SUID (runs with the file owner's privileges)
    Owner     : root (uid 0)
    Group     : root (gid 0)
    Reason    : GTFOBins match: can spawn a privileged shell when SUID is enabled.
```

### 2. Scan the whole filesystem

To scan from the root directory:

```bash
./suid_auditor.py
```

This can take more time. By default, the tool skips virtual filesystems like
`/proc`, `/sys`, `/dev`, and `/run` because they are noisy and can slow down
the scan.

### 3. Scan a custom directory

You can pass one or more directories:

```bash
./suid_auditor.py /usr/bin /bin /usr/local/bin
```

### 4. Show all SUID/SGID files

By default, SecurAudit only shows SUID/SGID files that match the built-in
GTFOBins risk list. To show every SUID/SGID file, use `--all`:

```bash
./suid_auditor.py --all /usr/bin
```

Common system binaries are shown as `Info` when they look expected. Unknown
files with SUID/SGID are shown as `Review` because they deserve manual
validation, but they are not automatically confirmed privilege escalation paths.

### 5. Use it in scripts or CI

Normal scans exit with status code `0`, even if findings are printed. If you
want the command to fail when risky findings are detected, use
`--fail-on-findings`:

```bash
./suid_auditor.py --fail-on-findings /usr/bin
```

This is useful for automation:

```bash
if ./suid_auditor.py --fail-on-findings /usr/bin; then
  echo "No risky SUID/SGID findings"
else
  echo "Risky SUID/SGID findings detected"
fi
```

## Options

```text
paths                 Directories to scan. Defaults to /.
--all                 Show every SUID/SGID file, not only GTFOBins matches.
--no-skip-virtual     Also scan /proc, /sys, /dev, and /run.
--fail-on-findings    Exit with code 1 when risky findings are detected.
```

## How to read the results

* `Level`: finding classification.
* `Permission`: whether the file has `SUID`, `SGID`, or both.
* `Owner`: owner user name and numeric UID.
* `Group`: group name and numeric GID.
* `Reason`: short explanation of why this binary is risky, expected, or worth reviewing.

Levels:

* `Critical` / `High`: GTFOBins match that crosses a privilege boundary, usually root-owned SUID. Review these first.
* `Review`: SUID/SGID exists on a file that is not classified as a common expected system binary.
* `Info`: common system binary with special permissions that are often normal.

`Info` is not an alert by itself. It means SecurAudit found a SUID/SGID file,
but it looks like a normal system binary where that permission is commonly
expected. For example, `sudo`, `su`, `passwd`, `mount`, and `umount` often need
SUID to work correctly. Treat `Info` as context, not as proof of a vulnerability.

Example:

```text
[1] /usr/bin/sudo
    Level     : Info
    Permission: SUID (runs with the file owner's privileges)
    Owner     : root (uid 0)
    Group     : root (gid 0)
    Reason    : Common system binary with expected special permissions; verify package integrity if unsure.
```

## What to do with findings

Do not remove SUID/SGID permissions blindly. Some system binaries need those
permissions to work correctly. For each finding:

1. Confirm whether the binary really needs SUID or SGID.
2. Check who owns it and whether it came from a trusted package.
3. Compare it with your distribution's default permissions.
4. Remove the special bit only if you are sure it is unnecessary:

```bash
sudo chmod u-s /path/to/binary
sudo chmod g-s /path/to/binary
```

For a quick local audit, this is a good starting command:

```bash
./suid_auditor.py --all /usr/bin /bin /usr/local/bin
```

## Troubleshooting

### I run it and nothing appears

If you run the tool without arguments:

```bash
./suid_auditor.py
```

it scans the whole filesystem from `/`. On large systems this can take a while.
For a faster test, scan only `/usr/bin`:

```bash
./suid_auditor.py /usr/bin
```

### It says no risky findings

That does not always mean there are no SUID/SGID files. By default, the tool
only shows matches against the built-in GTFOBins risk list. To see every
SUID/SGID file, use:

```bash
./suid_auditor.py --all /usr/bin
```

### Permission denied

Some directories require elevated permissions to read. You can either scan a
directory your user can access, or run a full audit with:

```bash
sudo ./suid_auditor.py --all /
```

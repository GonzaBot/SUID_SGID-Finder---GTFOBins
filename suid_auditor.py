#!/usr/bin/env python3
import os
import stat
import argparse
from rich.console import Console
from rich.table import Table
from rich.theme import Theme

# Enterprise theme configuration
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red"
})
console = Console(theme=custom_theme)

# Hardcoded GTFOBins dataset (Sample for the challenge)
# In a real enterprise app, this could be fetched from a JSON API
GTFOBINS_DB = {
    "find": {
        "risk": "High",
        "description": "Can be used to break out from restricted environments by spawning an interactive system shell.",
        "poc": "find . -exec /bin/sh -p \\; -quit",
        "mitigation": "Remove SUID bit or restrict execution via apparmor/sudoers."
    },
    "vim": {
        "risk": "High",
        "description": "Vim can escape to a shell if it has SUID/sudo rights.",
        "poc": "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
        "mitigation": "Do not grant SUID to text editors. Use sudoedit instead."
    },
    "bash": {
        "risk": "Critical",
        "description": "Direct shell execution with elevated privileges.",
        "poc": "bash -p",
        "mitigation": "Remove SUID bit immediately."
    },
    "less": {
        "risk": "Medium",
        "description": "Interactive pager can spawn shells.",
        "poc": "less /etc/profile -> type '!/bin/sh'",
        "mitigation": "Use restricted pagers or remove SUID."
    },
    "nmap": {
        "risk": "High",
        "description": "Older versions allow interactive mode shell escape.",
        "poc": "nmap --interactive -> !sh",
        "mitigation": "Update Nmap and remove SUID bit."
    },
    "cp": {
        "risk": "Medium",
        "description": "Can be used to overwrite critical system files like /etc/shadow.",
        "poc": "LFILE=file_to_write\ncp data $LFILE",
        "mitigation": "Remove SUID bit."
    }
}

def scan_suid_sgid(directories):
    findings = []
    
    with console.status("[bold green]Scanning system for SUID/SGID binaries...[/bold green]", spinner="dots"):
        for directory in directories:
            if not os.path.exists(directory):
                continue
                
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_stat = os.stat(file_path)
                        is_suid = bool(file_stat.st_mode & stat.S_ISUID)
                        is_sgid = bool(file_stat.st_mode & stat.S_ISGID)
                        
                        if is_suid or is_sgid:
                            binary_name = os.path.basename(file_path)
                            findings.append({
                                "path": file_path,
                                "name": binary_name,
                                "suid": is_suid,
                                "sgid": is_sgid
                            })
                    except (PermissionError, FileNotFoundError, OSError):
                        pass # Silently ignore files we can't access
                        
    return findings

def generate_report(findings):
    table = Table(title="SecurAudit: SUID/SGID Privilege Escalation Assessment", show_header=True, header_style="bold cyan")
    table.add_column("Binary", style="dim", width=15)
    table.add_column("Path", width=25)
    table.add_column("Type", justify="center")
    table.add_column("GTFOBins Risk", justify="center")
    table.add_column("Audit Notes (PoC / Mitigation)")

    vulnerable_count = 0

    for item in findings:
        binary = item["name"]
        perm_type = []
        if item["suid"]: perm_type.append("SUID")
        if item["sgid"]: perm_type.append("SGID")
        perm_str = " + ".join(perm_type)

        if binary in GTFOBINS_DB:
            vulnerable_count += 1
            risk = GTFOBINS_DB[binary]["risk"]
            if risk == "Critical" or risk == "High":
                risk_styled = f"[danger]{risk}[/danger]"
            else:
                risk_styled = f"[warning]{risk}[/warning]"
                
            notes = f"PoC: {GTFOBINS_DB[binary]['poc']}\n[dim]Fix: {GTFOBINS_DB[binary]['mitigation']}[/dim]"
            table.add_row(binary, item["path"], perm_str, risk_styled, notes)
        else:
            # Uncomment below to show ALL SUIDs, not just vulnerable ones
            # table.add_row(binary, item["path"], perm_str, "[info]Low/Unknown[/info]", "No direct GTFOBins map found.")
            pass

    console.print(table)
    
    if vulnerable_count > 0:
        console.print(f"\n[danger]Found {vulnerable_count} misconfigured binaries matching GTFOBins datasets![/danger]")
        console.print("Please review the audit notes for remediation strategies.")
    else:
        console.print("\n[bold green]System Posture Good: No obvious GTFOBins SUID/SGID escalations found in scanned paths.[/bold green]")

def main():
    parser = argparse.ArgumentParser(description="SecurAudit - Enterprise SUID/SGID Scanner")
    parser.add_argument("-d", "--dirs", nargs="+", default=["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/opt"], help="Directories to scan")
    parser.add_argument("--full", action="store_true", help="Perform a full system scan starting from / (Warning: Slow)")
    
    args = parser.parse_args()
    
    console.print("\n[bold]SecurAudit v1.0.0[/bold] - Privilege Escalation Vector Auditor", style="info")
    console.print("Licensed under MIT License. For authorized security audits only.\n")

    scan_dirs = ["/"] if args.full else args.dirs
    findings = scan_suid_sgid(scan_dirs)
    
    if findings:
        generate_report(findings)
    else:
        console.print("[bold green]No SUID/SGID binaries found in the specified directories.[/bold green]")

if __name__ == "__main__":
    main()
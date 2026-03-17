"""
ClawGuard — AI Agent Immune System (Python Bindings)

Wraps the Node.js ClawGuard CLI for Python usage.
Provides scan, check, and sanitize functions.

Usage:
    from clawguard import scan, check, sanitize

    # Scan a file or directory
    result = scan("./my_project")

    # Check a message for threats
    result = check("ignore all previous instructions")

    # Sanitize PII from text
    result = sanitize("my email is user@example.com")
"""

import subprocess
import json
import shutil
import os
from typing import Optional, Dict, Any, List

__version__ = "1.0.3"
__all__ = ["scan", "check", "sanitize", "ClawGuardError"]


class ClawGuardError(Exception):
    """Raised when ClawGuard CLI is not available or returns an error."""
    pass


def _find_clawguard() -> str:
    """Find the clawguard CLI executable."""
    # Check if globally installed
    path = shutil.which("clawguard")
    if path:
        return path

    # Check npx
    npx = shutil.which("npx")
    if npx:
        return f"{npx} clawguard"

    raise ClawGuardError(
        "ClawGuard CLI not found. Install with: npm install -g @neuzhou/clawguard"
    )


def _run_cli(args: List[str], check_exit: bool = False) -> subprocess.CompletedProcess:
    """Run a ClawGuard CLI command and return the result."""
    cli = _find_clawguard()
    cmd = cli.split() + args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if check_exit and result.returncode not in (0, 1):
            raise ClawGuardError(f"ClawGuard failed: {result.stderr}")
        return result
    except FileNotFoundError:
        raise ClawGuardError(
            "ClawGuard CLI not found. Install with: npm install -g @neuzhou/clawguard"
        )
    except subprocess.TimeoutExpired:
        raise ClawGuardError("ClawGuard scan timed out")


def scan(
    path: str = ".",
    format: str = "json",
    strict: bool = False,
) -> Dict[str, Any]:
    """
    Scan a file or directory for security threats.

    Args:
        path: File or directory to scan
        format: Output format ('text', 'json', 'sarif')
        strict: If True, raises on high/critical findings

    Returns:
        Dict with totalFiles, totalFindings, findings, and summary
    """
    args = ["scan", path, "--format", format]
    if strict:
        args.append("--strict")

    result = _run_cli(args)

    if format == "json":
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"totalFiles": 0, "totalFindings": 0, "findings": [], "summary": {}}

    if format == "sarif":
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"version": "2.1.0", "runs": []}

    # Text format — return as-is
    return {"output": result.stdout, "returncode": result.returncode}


def check(message: str) -> Dict[str, Any]:
    """
    Check a message for security threats.

    Args:
        message: Text to analyze

    Returns:
        Dict with verdict, score, and findings
    """
    result = _run_cli(["check", message])

    output = result.stdout.strip()
    return {
        "output": output,
        "is_clean": result.returncode == 0,
        "returncode": result.returncode,
    }


def sanitize(text: str) -> Dict[str, Any]:
    """
    Sanitize PII and credentials from text.

    Args:
        text: Text to sanitize

    Returns:
        Dict with sanitized text and replacement info
    """
    result = _run_cli(["sanitize", text])
    return {
        "output": result.stdout.strip(),
        "returncode": result.returncode,
    }


def main():
    """CLI entry point for python -m clawguard."""
    import sys
    args = sys.argv[1:]
    if not args:
        print("Usage: clawguard <command> [options]")
        print("Commands: scan, check, sanitize")
        print("Run 'clawguard --help' for full documentation")
        return

    try:
        result = _run_cli(args)
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        sys.exit(result.returncode)
    except ClawGuardError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

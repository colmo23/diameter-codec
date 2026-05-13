#!/usr/bin/env python3
"""
Diameter test harness.

Starts server.py and client.py as subprocesses, then sends every tgpp
message type via the client's HTTP API and reports results.

Usage
-----
    python test_harness.py [--tcp-port N] [--server-http N] [--client-http N]

Defaults use non-standard ports so the harness does not clash with a live
Diameter stack:  TCP 13868, server HTTP 18001, client HTTP 18002.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POLL_INTERVAL = 0.25
STARTUP_TIMEOUT = 20
DELIVERY_WAIT = 1.0

# ANSI colour helpers (disabled automatically if stdout is not a tty)
_USE_COLOR = sys.stdout.isatty()
_GREEN  = "\033[32m" if _USE_COLOR else ""
_RED    = "\033[31m" if _USE_COLOR else ""
_YELLOW = "\033[33m" if _USE_COLOR else ""
_RESET  = "\033[0m"  if _USE_COLOR else ""


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http(method: str, url: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()), resp.getcode()
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except Exception:
            return {"error": str(e)}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def _get(url):   return _http("GET", url)
def _delete(url): return _http("DELETE", url)
def _post(url, body=None): return _http("POST", url, body or {})


# ---------------------------------------------------------------------------
# Readiness polling
# ---------------------------------------------------------------------------

def _wait_http(base_url: str, label: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    sys.stdout.write(f"    {label:<36}")
    sys.stdout.flush()
    while time.time() < deadline:
        _, code = _get(f"{base_url}/status")
        if code == 200:
            print(f"{_GREEN}ready{_RESET}")
            return True
        time.sleep(POLL_INTERVAL)
        sys.stdout.write(".")
        sys.stdout.flush()
    print(f"{_RED}TIMEOUT{_RESET}")
    return False


def _wait_connected(client_url: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    sys.stdout.write(f"    {'client → server TCP':<36}")
    sys.stdout.flush()
    while time.time() < deadline:
        resp, code = _get(f"{client_url}/status")
        if code == 200 and resp.get("connected"):
            print(f"{_GREEN}connected{_RESET}")
            return True
        time.sleep(POLL_INTERVAL)
        sys.stdout.write(".")
        sys.stdout.flush()
    print(f"{_RED}TIMEOUT{_RESET}")
    return False


# ---------------------------------------------------------------------------
# Subprocess management
# ---------------------------------------------------------------------------

def _start(label: str, args: list, log_file) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable] + args,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        cwd=SCRIPT_DIR,
    )
    return proc


def _stop(proc: subprocess.Popen, label: str) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------

def _send_all(client_url: str, func_names: list) -> list:
    """POST /send/<func> for every function; return list of result dicts."""
    results = []
    name_w = max(len(n) for n in func_names) + 2
    for name in func_names:
        resp, code = _post(f"{client_url}/send/{name}")
        ok = code == 200
        command = resp.get("command", "")
        nbytes  = resp.get("bytes", 0)
        err     = resp.get("error", "")

        if ok:
            status_str = f"{_GREEN}OK  {_RESET}"
        else:
            status_str = f"{_RED}FAIL{_RESET}"

        detail = f"{command:<40} {nbytes:>6} bytes" if ok else f"{_RED}{err}{_RESET}"
        print(f"    {name:<{name_w}} {status_str}  {detail}")

        results.append({
            "func": name,
            "code": code,
            "ok": ok,
            "command": command,
            "bytes": nbytes,
            "error": err,
        })
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Diameter client/server test harness")
    parser.add_argument("--tcp-port",    type=int, default=13868, metavar="N",
                        help="TCP port for the Diameter server (default 13868)")
    parser.add_argument("--server-http", type=int, default=18001, metavar="N",
                        help="HTTP port for the server API    (default 18001)")
    parser.add_argument("--client-http", type=int, default=18002, metavar="N",
                        help="HTTP port for the client API    (default 18002)")
    args = parser.parse_args()

    server_url = f"http://127.0.0.1:{args.server_http}"
    client_url = f"http://127.0.0.1:{args.client_http}"

    server_proc = client_proc = None
    server_log  = client_log  = None

    print()
    print("=" * 64)
    print("  Diameter Client/Server Test Harness")
    print("=" * 64)

    try:
        # ------------------------------------------------------------------
        # Step 1 — start subprocesses
        # ------------------------------------------------------------------
        print(f"\n[1/5] Starting subprocesses")

        server_log = tempfile.TemporaryFile()
        server_proc = _start("server", [
            "server.py",
            "--tcp-host", "127.0.0.1",
            "--tcp-port", str(args.tcp_port),
            "--http-host", "127.0.0.1",
            "--http-port", str(args.server_http),
        ], server_log)
        print(f"    server  PID {server_proc.pid}  "
              f"(TCP 127.0.0.1:{args.tcp_port}  HTTP :{args.server_http})")

        client_log = tempfile.TemporaryFile()
        client_proc = _start("client", [
            "client.py",
            "--server-host", "127.0.0.1",
            "--server-port", str(args.tcp_port),
            "--http-host", "127.0.0.1",
            "--http-port", str(args.client_http),
        ], client_log)
        print(f"    client  PID {client_proc.pid}  "
              f"(→ TCP :{args.tcp_port}  HTTP :{args.client_http})")

        # ------------------------------------------------------------------
        # Step 2 — wait for readiness
        # ------------------------------------------------------------------
        print(f"\n[2/5] Waiting for readiness  (timeout {STARTUP_TIMEOUT}s)")

        if not _wait_http(server_url, "server HTTP API", STARTUP_TIMEOUT):
            _dump_logs("server", server_log)
            return 1
        if not _wait_http(client_url, "client HTTP API", STARTUP_TIMEOUT):
            _dump_logs("client", client_log)
            return 1
        if not _wait_connected(client_url, STARTUP_TIMEOUT):
            _dump_logs("client", client_log)
            _dump_logs("server", server_log)
            return 1

        # ------------------------------------------------------------------
        # Step 3 — discover functions
        # ------------------------------------------------------------------
        print(f"\n[3/5] Discovering available functions")
        resp, code = _get(f"{client_url}/functions")
        if code != 200:
            print(f"  {_RED}ERROR: could not fetch function list (HTTP {code}){_RESET}")
            return 1
        func_names = sorted(resp.keys())
        print(f"    {len(func_names)} tgpp functions registered")

        # Clear any leftover messages from the startup exchange
        _delete(f"{server_url}/messages")

        # ------------------------------------------------------------------
        # Step 4 — send every message type
        # ------------------------------------------------------------------
        print(f"\n[4/5] Sending all {len(func_names)} message types via client HTTP API")
        t0 = time.time()
        results = _send_all(client_url, func_names)
        elapsed = time.time() - t0
        print(f"\n    Completed in {elapsed:.2f}s")

        # ------------------------------------------------------------------
        # Step 5 — verify receipt on server
        # ------------------------------------------------------------------
        print(f"\n[5/5] Verifying receipt on server  (waiting {DELIVERY_WAIT}s)")
        time.sleep(DELIVERY_WAIT)
        srv_resp, _ = _get(f"{server_url}/messages")
        received = srv_resp.get("count", 0)

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        ok_count   = sum(1 for r in results if r["ok"])
        fail_count = len(results) - ok_count
        failed     = [r for r in results if not r["ok"]]

        print()
        print("=" * 64)
        print("  SUMMARY")
        print("=" * 64)
        print(f"    Functions registered : {len(func_names)}")
        _sline("Sent OK (HTTP 200)",   ok_count,   len(func_names), good=ok_count == len(func_names))
        _sline("Send errors",          fail_count, len(func_names), good=fail_count == 0, invert=True)
        _sline("Received by server",   received,   ok_count,        good=received >= ok_count)
        print(f"    Elapsed              : {elapsed:.2f}s")

        if failed:
            print(f"\n  {_RED}Failed sends:{_RESET}")
            for r in failed:
                print(f"    [{r['code']:3d}] {r['func']:<24}  {r['error']}")

        print("=" * 64)
        print()

        return 0 if fail_count == 0 else 1

    finally:
        _stop(client_proc, "client")
        _stop(server_proc, "server")
        if client_log:
            client_log.close()
        if server_log:
            server_log.close()


def _sline(label: str, value: int, total: int, good: bool, invert: bool = False) -> None:
    colour = _GREEN if good else _RED
    print(f"    {label:<28} {colour}{value:>4}{_RESET} / {total}")


def _dump_logs(label: str, fh) -> None:
    if fh is None:
        return
    fh.seek(0)
    content = fh.read().decode(errors="replace").strip()
    if content:
        print(f"\n--- {label} output ---")
        print(content)
        print("---")


if __name__ == "__main__":
    sys.exit(main())

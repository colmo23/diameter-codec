#!/usr/bin/env python3
"""
Diameter test harness.

Starts server.py and client.py as subprocesses, then sends every tgpp
message type via the client's HTTP API (using the DiameterAPI library) and
reports results.

Usage
-----
    python test_harness.py [--tcp-port N] [--server-http N] [--client-http N]

Defaults use non-standard ports so the harness does not clash with a live
Diameter stack:  TCP 13868, server HTTP 18001, client HTTP 18002.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time

from http_api import APIError, DiameterAPI, NotConnectedError


SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
POLL_INTERVAL   = 0.25
STARTUP_TIMEOUT = 20
DELIVERY_WAIT   = 1.0

# Example ULR: NTT Docomo Japan subscriber roaming in Ireland (Vodafone IE)
# IMSI: MCC=440 MNC=10 (NTT Docomo)
# Visited-PLMN-Id: MCC=272 MNC=01 (Vodafone Ireland) — 3GPP TS 24.008 §10.5.1.13 encoding
EXAMPLE_ULR = dict(
    origin_host      = "mme.mnc010.mcc440.3gppnetwork.org",
    origin_realm     = "mnc010.mcc440.3gppnetwork.org",
    destination_host = "hss.mnc010.mcc440.3gppnetwork.org",
    destination_realm= "mnc010.mcc440.3gppnetwork.org",
    user_name        = "440100123456789",
    rat_type         = "EUTRAN",
    ulr_flags        = 0x02,
    visited_plmn_id  = bytes.fromhex("72f210"),  # MCC=272 MNC=01
)

# ANSI colour helpers (disabled when stdout is not a tty)
_USE_COLOR = sys.stdout.isatty()
_GREEN  = "\033[32m" if _USE_COLOR else ""
_RED    = "\033[31m" if _USE_COLOR else ""
_RESET  = "\033[0m"  if _USE_COLOR else ""


# ---------------------------------------------------------------------------
# Readiness polling  (uses DiameterAPI)
# ---------------------------------------------------------------------------

def _wait_http(api: DiameterAPI, label: str, timeout: float) -> bool:
    """Poll api.status() until it succeeds or times out."""
    deadline = time.time() + timeout
    sys.stdout.write(f"    {label:<36}")
    sys.stdout.flush()
    while time.time() < deadline:
        try:
            api.status()
            print(f"{_GREEN}ready{_RESET}")
            return True
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)
        sys.stdout.write(".")
        sys.stdout.flush()
    print(f"{_RED}TIMEOUT{_RESET}")
    return False


def _wait_connected(client_api: DiameterAPI, timeout: float) -> bool:
    """Poll client_api.is_connected() until True or times out."""
    deadline = time.time() + timeout
    sys.stdout.write(f"    {'client → server TCP':<36}")
    sys.stdout.flush()
    while time.time() < deadline:
        try:
            if client_api.is_connected():
                print(f"{_GREEN}connected{_RESET}")
                return True
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)
        sys.stdout.write(".")
        sys.stdout.flush()
    print(f"{_RED}TIMEOUT{_RESET}")
    return False


# ---------------------------------------------------------------------------
# Subprocess management
# ---------------------------------------------------------------------------

def _start(args: list, log_file) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable] + args,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        cwd=SCRIPT_DIR,
    )


def _stop(proc: subprocess.Popen) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _dump_logs(label: str, fh) -> None:
    if fh is None:
        return
    fh.seek(0)
    content = fh.read().decode(errors="replace").strip()
    if content:
        print(f"\n--- {label} output ---")
        print(content)
        print("---")


# ---------------------------------------------------------------------------
# Sending  (uses DiameterAPI)
# ---------------------------------------------------------------------------

def _send_all(client_api: DiameterAPI, func_names: list) -> list:
    """
    Call client_api.send(func_name) for every function name.

    Returns a list of result dicts with keys:
        func, ok, command, bytes, error
    """
    results = []
    name_w = max(len(n) for n in func_names) + 2

    for name in func_names:
        try:
            resp = client_api.send(name)
            ok      = True
            command = resp.get("command", "")
            nbytes  = resp.get("bytes", 0)
            error   = ""
        except APIError as e:
            ok      = False
            command = ""
            nbytes  = 0
            error   = str(e)

        if ok:
            status_str = f"{_GREEN}OK  {_RESET}"
            detail = f"{command:<40} {nbytes:>6} bytes"
        else:
            status_str = f"{_RED}FAIL{_RESET}"
            detail = f"{_RED}{error}{_RESET}"

        print(f"    {name:<{name_w}} {status_str}  {detail}")

        results.append({
            "func":    name,
            "ok":      ok,
            "command": command,
            "bytes":   nbytes,
            "error":   error,
        })

    return results


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------

def _sline(label: str, value: int, total: int, good: bool) -> None:
    colour = _GREEN if good else _RED
    print(f"    {label:<28} {colour}{value:>4}{_RESET} / {total}")


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

    server_api = DiameterAPI(f"http://127.0.0.1:{args.server_http}")
    client_api = DiameterAPI(f"http://127.0.0.1:{args.client_http}")

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
        print(f"\n[1/6] Starting subprocesses")

        server_log  = tempfile.TemporaryFile()
        server_proc = _start([
            "server.py",
            "--tcp-host", "127.0.0.1",
            "--tcp-port", str(args.tcp_port),
            "--http-host", "127.0.0.1",
            "--http-port", str(args.server_http),
        ], server_log)
        print(f"    server  PID {server_proc.pid}  "
              f"(TCP 127.0.0.1:{args.tcp_port}  HTTP :{args.server_http})")

        client_log  = tempfile.TemporaryFile()
        client_proc = _start([
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
        print(f"\n[2/6] Waiting for readiness  (timeout {STARTUP_TIMEOUT}s)")

        if not _wait_http(server_api, "server HTTP API", STARTUP_TIMEOUT):
            _dump_logs("server", server_log)
            return 1
        if not _wait_http(client_api, "client HTTP API", STARTUP_TIMEOUT):
            _dump_logs("client", client_log)
            return 1
        if not _wait_connected(client_api, STARTUP_TIMEOUT):
            _dump_logs("client", client_log)
            _dump_logs("server", server_log)
            return 1

        # ------------------------------------------------------------------
        # Step 3 — discover functions
        # ------------------------------------------------------------------
        print(f"\n[3/6] Discovering available functions")

        func_names = client_api.list_functions()
        print(f"    {len(func_names)} tgpp functions registered")

        # Clear any messages that accumulated during startup
        server_api.clear_messages()
        client_api.clear_messages()

        # ------------------------------------------------------------------
        # Step 4 — example ULR: Japanese subscriber roaming in Ireland
        # ------------------------------------------------------------------
        print(f"\n[4/6] Example ULR — Japan IMSI roaming in Ireland")
        print(f"    IMSI          : {EXAMPLE_ULR['user_name']}  (NTT Docomo MCC=440 MNC=10)")
        print(f"    Visited-PLMN  : {EXAMPLE_ULR['visited_plmn_id'].hex()}  (Vodafone Ireland MCC=272 MNC=01)")

        client_api.send("ulr", **EXAMPLE_ULR)
        time.sleep(0.3)

        example_msgs = server_api.get_messages()
        if example_msgs:
            m = example_msgs[0]
            print(f"    Received by server:")
            print(f"      command        : {m.command}")
            print(f"      app_id         : {m.app_id}  (S6a)")
            print(f"      User-Name      : {m.get_avp_value('User-Name')}")
            print(f"      Visited-PLMN-Id: {m.get_avp_value('Visited-PLMN-Id')}")
            print(f"      RAT-Type       : {m.get_avp_value('RAT-Type')}")
            print(f"      wire bytes     : {len(m.raw_bytes())}")
        else:
            print(f"    {_RED}ERROR: server received no messages{_RESET}")

        server_api.clear_messages()

        # ------------------------------------------------------------------
        # Step 5 — send every message type
        # ------------------------------------------------------------------
        print(f"\n[5/6] Sending all {len(func_names)} message types via client API")
        t0      = time.time()
        results = _send_all(client_api, func_names)
        elapsed = time.time() - t0
        print(f"\n    Completed in {elapsed:.2f}s")

        # ------------------------------------------------------------------
        # Step 6 — verify receipt on server
        # ------------------------------------------------------------------
        print(f"\n[6/6] Verifying receipt on server  (waiting {DELIVERY_WAIT}s)")
        time.sleep(DELIVERY_WAIT)

        received = len(server_api.get_messages())

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
        _sline("Sent OK (HTTP 200)",  ok_count,   len(func_names), good=ok_count == len(func_names))
        _sline("Send errors",         fail_count, len(func_names), good=fail_count == 0)
        _sline("Received by server",  received,   ok_count,        good=received >= ok_count)
        print(f"    Elapsed              : {elapsed:.2f}s")

        if failed:
            print(f"\n  {_RED}Failed sends:{_RESET}")
            for r in failed:
                print(f"    {r['func']:<24}  {r['error']}")

        print("=" * 64)
        print()

        return 0 if fail_count == 0 else 1

    finally:
        _stop(client_proc)
        _stop(server_proc)
        if client_log:
            client_log.close()
        if server_log:
            server_log.close()


if __name__ == "__main__":
    sys.exit(main())

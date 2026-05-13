#!/usr/bin/env python3
"""
Diameter TCP client with HTTP management API.

    python client.py [--server-host HOST] [--server-port PORT]
                     [--http-host HOST]   [--http-port PORT]

Defaults
--------
  Server TCP : 127.0.0.1:3868
  HTTP       : 127.0.0.1:8002

The client reconnects automatically whenever the connection drops.

HTTP endpoints
--------------
  GET    /messages           List received messages as JSON.
                             Add ?download=1 to get a file attachment.
  DELETE /messages           Clear received messages.
  GET    /functions          List all tgpp factory functions + parameter schemas.
  GET    /functions/<name>   Schema for a single function.
  POST   /send/<func>        Build and send a message to the server.
                             Body: JSON object with the function's kwargs.
                             bytes parameters take hex strings, e.g. {"visited_plmn_id": "00f110"}.
  GET    /status             Connection state.
"""

import argparse
import json
import socket
import threading
import time
from typing import Optional

from flask import Flask, Response, jsonify, request

import peer

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_received: list = []
_sock: Optional[socket.socket] = None
_connected: bool = False
_server_addr: str = ""

MAX_MESSAGES = 5000


def _store(d: dict) -> None:
    with _lock:
        _received.append(d)
        if len(_received) > MAX_MESSAGES:
            del _received[0]


def _send(raw: bytes) -> bool:
    with _lock:
        s = _sock
    if s is None:
        return False
    try:
        s.sendall(raw)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# TCP client
# ---------------------------------------------------------------------------

def _reader_loop(sock: socket.socket, server: str) -> None:
    while True:
        raw = peer.read_message(sock)
        if raw is None:
            break
        msg = peer.decode_message(raw)
        if msg:
            d = peer.msg_to_dict(msg, source=server, raw=raw)
            _store(d)
            print(f"[TCP] recv  {msg.command!r}  from {server}")


def _connect_loop(host: str, port: int) -> None:
    global _sock, _connected, _server_addr
    _server_addr = f"{host}:{port}"
    while True:
        try:
            print(f"[TCP] connecting to {_server_addr} ...")
            s = socket.create_connection((host, port), timeout=5)
            s.settimeout(None)
            with _lock:
                _sock = s
                _connected = True
            print(f"[TCP] connected to {_server_addr}")
            _reader_loop(s, _server_addr)
        except OSError as e:
            print(f"[TCP] error: {e}")
        finally:
            with _lock:
                _connected = False
                _sock = None
        print("[TCP] reconnecting in 5 s ...")
        time.sleep(5)


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/messages", methods=["GET"])
def get_messages():
    with _lock:
        data = list(_received)
    payload = json.dumps({"count": len(data), "messages": data}, indent=2)
    if request.args.get("download"):
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=messages.json"},
        )
    return Response(payload, mimetype="application/json")


@app.route("/messages", methods=["DELETE"])
def clear_messages():
    with _lock:
        count = len(_received)
        _received.clear()
    return jsonify({"cleared": count})


@app.route("/functions", methods=["GET"])
def list_functions():
    return jsonify(peer.all_schemas())


@app.route("/functions/<func_name>", methods=["GET"])
def get_function(func_name):
    func = peer.TGPP_FUNCTIONS.get(func_name)
    if func is None:
        return jsonify({"error": f"Unknown function: {func_name!r}"}), 404
    return jsonify(peer.function_schema(func))


@app.route("/send/<func_name>", methods=["POST"])
def send_message(func_name):
    body = request.get_json(silent=True) or {}
    try:
        msg = peer.build_message(func_name, body)
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    raw = peer.encode_message(msg)
    if not _send(raw):
        return jsonify({"error": "not connected to server"}), 503
    return jsonify({
        "sent": True,
        "bytes": len(raw),
        "command": msg.command,
        "is_request": msg.is_request,
    })


@app.route("/status", methods=["GET"])
def status():
    with _lock:
        connected = _connected
        received = len(_received)
        server = _server_addr
    return jsonify({
        "connected": connected,
        "server": server,
        "received_messages": received,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Diameter TCP client + HTTP API")
    parser.add_argument("--server-host", default="127.0.0.1", metavar="HOST")
    parser.add_argument("--server-port", type=int, default=3868, metavar="PORT")
    parser.add_argument("--http-host", default="127.0.0.1", metavar="HOST")
    parser.add_argument("--http-port", type=int, default=8002, metavar="PORT")
    args = parser.parse_args()

    threading.Thread(
        target=_connect_loop,
        args=(args.server_host, args.server_port),
        daemon=True,
    ).start()

    print(f"[HTTP] API on http://{args.http_host}:{args.http_port}")
    app.run(host=args.http_host, port=args.http_port, use_reloader=False)


if __name__ == "__main__":
    main()

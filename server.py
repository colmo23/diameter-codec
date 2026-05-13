#!/usr/bin/env python3
"""
Diameter TCP server with HTTP management API.

    python server.py [--tcp-host HOST] [--tcp-port PORT]
                     [--http-host HOST] [--http-port PORT]

Defaults
--------
  TCP  : 0.0.0.0:3868  (RFC 6733 default Diameter port)
  HTTP : 127.0.0.1:8001

HTTP endpoints
--------------
  GET    /messages           List received messages as JSON.
                             Add ?download=1 to get a file attachment.
  DELETE /messages           Clear received messages.
  GET    /functions          List all tgpp factory functions + parameter schemas.
  GET    /functions/<name>   Schema for a single function.
  POST   /send/<func>        Build and broadcast a message to all connected clients.
                             Body: JSON object with the function's kwargs.
                             bytes parameters take hex strings, e.g. {"visited_plmn_id": "00f110"}.
  GET    /status             Number of connected clients.
"""

import argparse
import json
import socket
import threading

from flask import Flask, Response, jsonify, request

import peer

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_received: list = []           # list of dicts from peer.msg_to_dict
_clients: list = []            # live socket objects

MAX_MESSAGES = 5000


def _store(d: dict) -> None:
    with _lock:
        _received.append(d)
        if len(_received) > MAX_MESSAGES:
            del _received[0]


def _broadcast(raw: bytes) -> int:
    """Send raw bytes to every connected client; return number of recipients."""
    with _lock:
        clients = list(_clients)
    dead = []
    for sock in clients:
        try:
            sock.sendall(raw)
        except OSError:
            dead.append(sock)
    if dead:
        with _lock:
            for s in dead:
                if s in _clients:
                    _clients.remove(s)
    return len(clients) - len(dead)


# ---------------------------------------------------------------------------
# TCP server
# ---------------------------------------------------------------------------

def _handle_client(conn: socket.socket, addr) -> None:
    source = f"{addr[0]}:{addr[1]}"
    print(f"[TCP] connected  {source}")
    with _lock:
        _clients.append(conn)
    try:
        while True:
            raw = peer.read_message(conn)
            if raw is None:
                break
            msg = peer.decode_message(raw)
            if msg:
                d = peer.msg_to_dict(msg, source=source, raw=raw)
                _store(d)
                print(f"[TCP] recv  {msg.command!r}  from {source}")
    finally:
        with _lock:
            if conn in _clients:
                _clients.remove(conn)
        conn.close()
        print(f"[TCP] disconnected  {source}")


def _accept_loop(host: str, port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(32)
    print(f"[TCP] listening on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle_client, args=(conn, addr), daemon=True).start()


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
    sent_to = _broadcast(raw)
    return jsonify({
        "sent_to": sent_to,
        "bytes": len(raw),
        "command": msg.command,
        "is_request": msg.is_request,
    })


@app.route("/status", methods=["GET"])
def status():
    with _lock:
        n = len(_clients)
        received = len(_received)
    return jsonify({"connected_clients": n, "received_messages": received})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Diameter TCP server + HTTP API")
    parser.add_argument("--tcp-host", default="0.0.0.0", metavar="HOST")
    parser.add_argument("--tcp-port", type=int, default=3868, metavar="PORT")
    parser.add_argument("--http-host", default="127.0.0.1", metavar="HOST")
    parser.add_argument("--http-port", type=int, default=8001, metavar="PORT")
    args = parser.parse_args()

    threading.Thread(
        target=_accept_loop,
        args=(args.tcp_host, args.tcp_port),
        daemon=True,
    ).start()

    print(f"[HTTP] API on http://{args.http_host}:{args.http_port}")
    app.run(host=args.http_host, port=args.http_port, use_reloader=False)


if __name__ == "__main__":
    main()

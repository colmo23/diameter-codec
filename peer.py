"""
Shared utilities for the Diameter TCP client/server pair.

Provides TCP message framing, JSON serialisation, and a tgpp function
registry with automatic type coercion from JSON request bodies.
"""

import inspect
import sys
import threading
import typing
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

# typing.get_origin / get_args were added in Python 3.8
if sys.version_info >= (3, 8):
    from typing import get_origin as _get_origin, get_args as _get_args
else:
    def _get_origin(tp):
        return getattr(tp, "__origin__", None)

    def _get_args(tp):
        return getattr(tp, "__args__", None) or ()

from diameter import Dictionary, Message
from diameter import tgpp
from diameter.avp import AVP as _AVP

_DICT = Dictionary()


# ---------------------------------------------------------------------------
# TCP framing
# ---------------------------------------------------------------------------

def _recv_n(sock, n: int) -> Optional[bytes]:
    """Read exactly n bytes from a blocking socket, or None on EOF/error."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def read_message(sock) -> Optional[bytes]:
    """
    Read one complete Diameter message from sock.

    Diameter messages are self-delimiting: the total length is encoded in
    bytes 1-3 of the 20-byte fixed header.  Returns None on EOF or error.
    """
    hdr = _recv_n(sock, 4)
    if hdr is None:
        return None
    total = (hdr[1] << 16) | (hdr[2] << 8) | hdr[3]
    if total < 20:
        return None
    rest = _recv_n(sock, total - 4)
    return (hdr + rest) if rest is not None else None


def decode_message(raw: bytes) -> Optional[Message]:
    try:
        return Message.decode(raw, _DICT)
    except Exception:
        return None


def encode_message(msg: Message) -> bytes:
    return msg.encode(_DICT)


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

def _val_to_json(v: Any) -> Any:
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, list):
        return [avp_to_dict(a) for a in v]
    return v


def avp_to_dict(avp: _AVP) -> Dict:
    return {"name": avp.name, "value": _val_to_json(avp.value)}


def msg_to_dict(msg: Message, source: str = "", raw: bytes = b"") -> Dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "command": msg.command,
        "is_request": msg.is_request,
        "is_proxiable": msg.is_proxiable,
        "is_error": msg.is_error,
        "app_id": msg.app_id,
        "hop_by_hop_id": msg.hop_by_hop_id,
        "end_to_end_id": msg.end_to_end_id,
        "avps": [avp_to_dict(a) for a in msg.avps],
        "raw_hex": raw.hex(),
    }


# ---------------------------------------------------------------------------
# tgpp function registry
# ---------------------------------------------------------------------------

def _origin_is_list(origin) -> bool:
    """True if origin represents a list generic (handles 3.6 and 3.7+ differences)."""
    if origin is None:
        return False
    if origin is list:
        return True
    # Python 3.6: List[X].__origin__ is typing.List (the unparameterised alias)
    if origin is typing.List:
        return True
    return getattr(origin, "_name", None) == "List"


def _is_avp_list(ann) -> bool:
    """Return True if ann is List[AVP] or Optional[List[AVP]]."""
    origin = _get_origin(ann)
    args = _get_args(ann)
    if origin is typing.Union and type(None) in args:
        inner = [a for a in args if a is not type(None)]
        return _is_avp_list(inner[0]) if inner else False
    if _origin_is_list(origin) and args:
        return args[0] is _AVP
    return False


def _ptype(ann) -> str:
    """Classify an annotation into a simple type name for JSON coercion."""
    if ann is inspect.Parameter.empty:
        return "any"
    origin = _get_origin(ann)
    args = _get_args(ann)
    if origin is typing.Union and type(None) in args:
        inner = [a for a in args if a is not type(None)]
        return _ptype(inner[0]) if inner else "any"
    if ann is str:   return "str"
    if ann is int:   return "int"
    if ann is bytes: return "bytes_hex"
    if ann is bool:  return "bool"
    if ann is float: return "float"
    if _origin_is_list(origin) and args and args[0] is int:
        return "list_int"
    return "any"


TGPP_FUNCTIONS: Dict[str, Callable] = {
    name: obj
    for name, obj in inspect.getmembers(tgpp, inspect.isfunction)
    if not name.startswith("_")
}


def function_schema(func: Callable) -> Dict:
    """Return a JSON-serialisable description of a tgpp factory function."""
    sig = inspect.signature(func)
    params: Dict[str, Any] = {}
    for pname, param in sig.parameters.items():
        if _is_avp_list(param.annotation):
            continue
        entry: Dict[str, Any] = {"type": _ptype(param.annotation)}
        if param.default is not inspect.Parameter.empty:
            d = param.default
            entry["default"] = d.hex() if isinstance(d, bytes) else d
        params[pname] = entry
    return {"parameters": params}


def all_schemas() -> Dict[str, Any]:
    return {name: function_schema(f) for name, f in TGPP_FUNCTIONS.items()}


def build_kwargs(func: Callable, body: Dict) -> Dict:
    """Convert a JSON body dict into typed kwargs suitable for calling func."""
    sig = inspect.signature(func)
    kwargs: Dict[str, Any] = {}
    for pname, param in sig.parameters.items():
        if _is_avp_list(param.annotation) or pname not in body:
            continue
        v = body[pname]
        if v is None:
            kwargs[pname] = None
            continue
        t = _ptype(param.annotation)
        if t == "bytes_hex" and isinstance(v, str):
            v = bytes.fromhex(v)
        elif t == "int":
            v = int(v)
        elif t == "float":
            v = float(v)
        elif t == "list_int" and isinstance(v, list):
            v = [int(x) for x in v]
        kwargs[pname] = v
    return kwargs


def build_message(func_name: str, body: Dict) -> Message:
    """Look up a tgpp factory by name, coerce args from body, and call it."""
    func = TGPP_FUNCTIONS.get(func_name)
    if func is None:
        raise KeyError(f"Unknown function: {func_name!r}")
    return func(**build_kwargs(func, body))


# ---------------------------------------------------------------------------
# Auto-response engine
# ---------------------------------------------------------------------------

# Maps incoming Diameter command name → tgpp answer-function name.
REQUEST_TO_ANSWER: Dict[str, str] = {
    "3GPP-Update-Location":             "ula",
    "3GPP-Authentication-Information":  "aia",
    "3GPP-Cancel-Location":             "cla",
    "3GPP-Insert-Subscriber-Data":      "ida",
    "3GPP-Delete-Subscriber-Data":      "dsa",
    "3GPP-Purge-UE":                    "pua_s6a",
    "3GPP-Reset":                       "rsa_s6a",
    "3GPP-Notify":                      "noa",
    "Location-Info":                    "lia",
    "Multimedia-Auth":                  "maa",
    "Server-Assignment":                "saa",
    "Registration-Termination":         "rta",
    "Push-Profile":                     "ppa",
    "User-Data":                        "uda",
    "Profile-Update":                   "pua_sh",
    "Subscribe-Notifications":          "sna",
    "Push-Notification":                "pna",
    "AA":                               "aaa_rx",
    "Session-Termination":              "sta_rx",
    "Re-Auth":                          "raa_rx",
    "Abort-Session":                    "asa_rx",
    "Credit-Control":                   "cca_gx",
    "Capabilities-Exchange":            "cea",
    "Device-Watchdog":                  "dwa",
    "Disconnect-Peer":                  "dpa",
    "UA":                               "uaa",
}

_resp_lock = threading.Lock()
_response_rules: Dict[str, Dict] = {}


def set_response_rule(command: str, kwargs: Dict) -> None:
    """Register auto-response kwargs overrides for requests with *command*."""
    with _resp_lock:
        _response_rules[command] = dict(kwargs)


def get_response_rule(command: str) -> Optional[Dict]:
    with _resp_lock:
        rule = _response_rules.get(command)
        return dict(rule) if rule is not None else None


def delete_response_rule(command: str) -> bool:
    with _resp_lock:
        return _response_rules.pop(command, None) is not None


def all_response_rules() -> Dict[str, Dict]:
    with _resp_lock:
        return {k: dict(v) for k, v in _response_rules.items()}


def build_auto_response(msg: Message) -> Optional[bytes]:
    """
    Build and encode an answer for an incoming request message.

    The Session-Id is mirrored from the request unless the rule overrides it.
    Returns None when no rule is registered for the command or when *msg* is
    itself an answer.
    """
    if not msg.is_request:
        return None
    rule = get_response_rule(msg.command)
    if rule is None:
        return None
    func_name = REQUEST_TO_ANSWER.get(msg.command)
    if func_name is None:
        return None
    func = TGPP_FUNCTIONS.get(func_name)
    if func is None:
        return None

    merged = dict(rule)
    sid_avp = msg.get_avp("Session-Id")
    if sid_avp is not None and "session_id" not in merged:
        merged["session_id"] = sid_avp.value

    try:
        return encode_message(func(**build_kwargs(func, merged)))
    except Exception as exc:
        print(f"[auto-response] error building {func_name!r}: {exc}")
        return None

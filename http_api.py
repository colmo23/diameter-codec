"""
Diameter HTTP API message factory library.

Provides a Python client for the HTTP management APIs exposed by server.py
and client.py.  Handles type conversion automatically (bytes ↔ hex strings)
and exposes every tgpp factory function as a direct method call.

Quick start
-----------
    from http_api import DiameterAPI

    # Point at whichever peer you want to drive
    client = DiameterAPI("http://127.0.0.1:8002")   # client's API
    server = DiameterAPI("http://127.0.0.1:8001")   # server's API

    # Send a message — kwargs match the tgpp function signature exactly.
    # bytes values are converted to/from hex automatically.
    client.send("ulr",
        origin_host="mme.mnc051.mcc262.3gppnetwork.org",
        user_name="262051234567890",
        visited_plmn_id=b"\\x62\\xf2\\x10",
    )

    # Shorthand: api.<func_name>(**kwargs)
    client.cer(origin_host="mme.example.com", host_ip_address="10.0.0.1")
    client.ccr_gx(cc_request_type="INITIAL_REQUEST", cc_request_number=0)

    # Received messages
    msgs = client.get_messages()         # list[Message]
    for m in msgs:
        print(m.command, m.get_avp("Origin-Host"))
    client.clear_messages()

    # Save all received messages to a file
    client.download_messages("received.json")

    # Introspect a factory function's parameters
    schema = client.get_schema("ulr")
    for param, info in schema["parameters"].items():
        print(param, info["type"], info.get("default"))
"""

import inspect
import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

import peer


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class APIError(Exception):
    """Raised when the server returns a non-2xx HTTP response."""

    def __init__(self, code: int, body: dict) -> None:
        self.code = code
        self.body = body
        msg = body.get("error") or json.dumps(body)
        super().__init__(f"HTTP {code}: {msg}")


class NotConnectedError(APIError):
    """Raised on HTTP 503 — peer is not connected to its counterpart."""


# ---------------------------------------------------------------------------
# Message wrapper
# ---------------------------------------------------------------------------

class Message:
    """
    A received Diameter message returned by :meth:`DiameterAPI.get_messages`.

    AVP values use the same representations as the HTTP API:
    bytes-typed AVPs are hex strings, grouped AVPs are nested dicts.
    """

    def __init__(self, data: dict) -> None:
        self._data = data

    # --- header fields ---

    @property
    def timestamp(self) -> str:
        """ISO-8601 UTC timestamp of receipt."""
        return self._data.get("timestamp", "")

    @property
    def source(self) -> str:
        """``"ip:port"`` string identifying the sender."""
        return self._data.get("source", "")

    @property
    def command(self) -> str:
        """Diameter command name, e.g. ``"3GPP-Update-Location"``."""
        return self._data.get("command", "")

    @property
    def is_request(self) -> bool:
        return bool(self._data.get("is_request"))

    @property
    def is_proxiable(self) -> bool:
        return bool(self._data.get("is_proxiable"))

    @property
    def is_error(self) -> bool:
        return bool(self._data.get("is_error"))

    @property
    def app_id(self) -> int:
        return int(self._data.get("app_id", 0))

    @property
    def hop_by_hop_id(self) -> int:
        return int(self._data.get("hop_by_hop_id", 0))

    @property
    def end_to_end_id(self) -> int:
        return int(self._data.get("end_to_end_id", 0))

    # --- AVPs ---

    @property
    def avps(self) -> List[dict]:
        """Ordered list of AVP dicts: ``{"name": str, "value": ...}``."""
        return self._data.get("avps", [])

    def get_avp(self, name: str) -> Optional[dict]:
        """Return the first AVP dict with the given name, or ``None``."""
        for avp in self.avps:
            if avp["name"] == name:
                return avp
        return None

    def get_avps(self, name: str) -> List[dict]:
        """Return every AVP dict with the given name."""
        return [a for a in self.avps if a["name"] == name]

    def get_avp_value(self, name: str) -> Any:
        """Return the value of the first AVP with the given name, or ``None``."""
        avp = self.get_avp(name)
        return avp["value"] if avp else None

    # --- raw bytes ---

    @property
    def raw_hex(self) -> str:
        """Wire bytes as a hex string."""
        return self._data.get("raw_hex", "")

    def raw_bytes(self) -> bytes:
        """Wire bytes as a :class:`bytes` object."""
        return bytes.fromhex(self.raw_hex)

    # --- misc ---

    def to_dict(self) -> dict:
        """Return the underlying dict (as received from the HTTP API)."""
        return dict(self._data)

    def __repr__(self) -> str:
        direction = "Request" if self.is_request else "Answer"
        return f"Message({self.command!r}, {direction}, app_id={self.app_id})"


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _to_json_body(func, kwargs: dict) -> dict:
    """
    Convert Python kwargs into a JSON-serialisable dict for the HTTP API.

    The only conversion required is ``bytes`` → hex string; the HTTP API
    handles all other types (str, int, float, list[int]) natively.
    """
    result: Dict[str, Any] = {}
    for key, value in kwargs.items():
        if isinstance(value, bytes):
            result[key] = value.hex()
        elif isinstance(value, (list, tuple)) and value and isinstance(value[0], bytes):
            result[key] = [v.hex() if isinstance(v, bytes) else v for v in value]
        else:
            result[key] = value
    return result


def _build_default_body(func) -> dict:
    """
    Build a JSON body using every parameter's default value.

    Used to pre-populate schemas with example values.
    """
    sig = inspect.signature(func)
    body: Dict[str, Any] = {}
    for pname, param in sig.parameters.items():
        if peer._is_avp_list(param.annotation):
            continue
        if param.default is inspect.Parameter.empty:
            continue
        d = param.default
        body[pname] = d.hex() if isinstance(d, bytes) else d
    return body


# ---------------------------------------------------------------------------
# Main API class
# ---------------------------------------------------------------------------

class DiameterAPI:
    """
    HTTP client for the Diameter TCP peer API.

    Parameters
    ----------
    base_url : str
        Base URL of the server or client HTTP API.
        Typically ``"http://127.0.0.1:8001"`` (server) or
        ``"http://127.0.0.1:8002"`` (client).
    timeout : float
        Request timeout in seconds (default 10).

    Shorthand call syntax
    ---------------------
    Any tgpp factory function name can be called directly on the instance::

        api.ulr(user_name="001010123456789")
        api.cer(host_ip_address="10.0.0.1")
        api.ccr_gx(cc_request_type="UPDATE_REQUEST", cc_request_number=1)

    This is equivalent to ``api.send("<name>", **kwargs)``.
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Internal HTTP
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        url = self.base_url + path
        data = json.dumps(body).encode() if body is not None else None
        headers: Dict[str, str] = {}
        if data:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read())
            except Exception:
                err_body = {"error": str(e)}
            if e.code == 503:
                raise NotConnectedError(e.code, err_body)
            raise APIError(e.code, err_body)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """
        Return connection state and message count.

        Server response: ``{"connected_clients": N, "received_messages": N}``

        Client response: ``{"connected": bool, "server": "ip:port",
        "received_messages": N}``
        """
        return self._request("GET", "/status")

    def is_connected(self) -> bool:
        """
        Return whether this peer has an active Diameter TCP connection.

        For the client, checks ``connected``.
        For the server, checks ``connected_clients > 0``.
        """
        s = self.status()
        return s.get("connected", False) or s.get("connected_clients", 0) > 0

    # ------------------------------------------------------------------
    # Received messages
    # ------------------------------------------------------------------

    def get_messages(self) -> List[Message]:
        """
        Return all messages received so far as a list of :class:`Message`.

        Returns an empty list if none have arrived yet.
        """
        resp = self._request("GET", "/messages")
        return [Message(m) for m in resp.get("messages", [])]

    def get_messages_raw(self) -> dict:
        """Return the raw ``{"count": N, "messages": [...]}`` dict."""
        return self._request("GET", "/messages")

    def clear_messages(self) -> int:
        """
        Clear all received messages.

        Returns the number of messages that were cleared.
        """
        resp = self._request("DELETE", "/messages")
        return resp.get("cleared", 0)

    def download_messages(self, path: str) -> int:
        """
        Save all received messages to *path* as a JSON file.

        Returns the number of messages saved.
        """
        url = self.base_url + "/messages?download=1"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read()
        with open(path, "wb") as fh:
            fh.write(raw)
        try:
            return json.loads(raw).get("count", 0)
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Function schemas
    # ------------------------------------------------------------------

    def get_all_schemas(self) -> dict:
        """
        Return schemas for all registered tgpp factory functions.

        Each entry maps a function name to
        ``{"parameters": {name: {"type": ..., "default": ...}, ...}}``.
        """
        return self._request("GET", "/functions")

    def get_schema(self, func_name: str) -> dict:
        """
        Return the parameter schema for one factory function.

        Raises :class:`APIError` (404) if *func_name* is unknown.
        """
        return self._request("GET", f"/functions/{func_name}")

    def list_functions(self) -> List[str]:
        """Return a sorted list of all available factory function names."""
        return sorted(self.get_all_schemas().keys())

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def send(self, func_name: str, **kwargs) -> dict:
        """
        Build and send a Diameter message.

        Parameters
        ----------
        func_name : str
            Name of a tgpp factory function, e.g. ``"ulr"``, ``"ccr_gx"``.
        **kwargs
            Arguments for the factory function.  Unspecified args use the
            function's built-in defaults.  ``bytes`` values are converted to
            hex strings automatically.

        Returns
        -------
        dict
            ``{"sent": true, "bytes": N, "command": "...", "is_request": bool}``
            (client) or ``{"sent_to": N, ...}`` (server).

        Raises
        ------
        APIError
            404 if *func_name* is unknown; 400 if the message cannot be built.
        NotConnectedError
            503 if the peer has no active TCP connection.
        """
        func = peer.TGPP_FUNCTIONS.get(func_name)
        body = _to_json_body(func, kwargs) if func else {
            k: v.hex() if isinstance(v, bytes) else v for k, v in kwargs.items()
        }
        return self._request("POST", f"/send/{func_name}", body)

    def send_all(self, func_name: str) -> dict:
        """
        Send a message using all default parameter values.

        Convenience wrapper around ``send(func_name)`` with no overrides.
        """
        return self.send(func_name)

    # ------------------------------------------------------------------
    # Shorthand: api.<func_name>(**kwargs)
    # ------------------------------------------------------------------

    def __getattr__(self, name: str):
        """
        Delegate ``api.<func_name>(**kwargs)`` to ``api.send(func_name, **kwargs)``.

        Only fires for names that are registered tgpp factory functions;
        all other missing attributes raise :class:`AttributeError` normally.
        """
        if name.startswith("_") or name not in peer.TGPP_FUNCTIONS:
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute {name!r}"
            )
        func = peer.TGPP_FUNCTIONS[name]

        def _sender(**kwargs):
            return self.send(name, **kwargs)

        _sender.__name__ = name
        _sender.__qualname__ = f"{type(self).__name__}.{name}"
        _sender.__doc__ = func.__doc__
        return _sender

    def __repr__(self) -> str:
        return f"DiameterAPI({self.base_url!r})"


# ---------------------------------------------------------------------------
# Module-level convenience: build_payload
# ---------------------------------------------------------------------------

def build_payload(func_name: str, **kwargs) -> dict:
    """
    Build the JSON body dict for a tgpp factory function without making an
    HTTP call.

    Useful for inspecting what would be sent, or for constructing batch
    request bodies.

    Parameters
    ----------
    func_name : str
        Name of the tgpp factory function.
    **kwargs
        Keyword arguments; ``bytes`` values are converted to hex strings.

    Returns
    -------
    dict
        JSON-serialisable body ready for ``POST /send/<func_name>``.

    Raises
    ------
    KeyError
        If *func_name* is not a registered tgpp function.

    Examples
    --------
    >>> build_payload("ulr", user_name="001010123456789", visited_plmn_id=b"\\x00\\xf1\\x10")
    {'user_name': '001010123456789', 'visited_plmn_id': '00f110'}
    """
    func = peer.TGPP_FUNCTIONS.get(func_name)
    if func is None:
        raise KeyError(f"Unknown tgpp function: {func_name!r}")
    return _to_json_body(func, kwargs)


def default_payload(func_name: str) -> dict:
    """
    Return a JSON body containing each parameter's default value.

    Useful for discovering what a factory function sends by default.

    Raises
    ------
    KeyError
        If *func_name* is not a registered tgpp function.
    """
    func = peer.TGPP_FUNCTIONS.get(func_name)
    if func is None:
        raise KeyError(f"Unknown tgpp function: {func_name!r}")
    return _build_default_body(func)

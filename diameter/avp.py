"""
Diameter AVP encoding and decoding.

Wire format (RFC 6733 §4.1)
---------------------------
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           AVP Code                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V M P r r r r r|                  AVP Length                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Vendor-ID (opt)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Data ...
+-+-+-+-+-+-+-+-+

* V = vendor-specific bit (0x80)
* M = mandatory bit      (0x40)
* P = protected bit      (0x20)
* AVP Length includes header + vendor-ID (if present) + data; NOT padding.
* Data is zero-padded to the next 4-byte boundary (padding not counted).

Address encoding (RFC 6733 §4.3.1)
------------------------------------
The Address type is prefixed with a 2-byte address-family number:
  1 → IPv4 (4 bytes follow)
  2 → IPv6 (16 bytes follow)
"""

import socket
import struct
from typing import Any, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .dictionary import Dictionary, AVPDef

# Flag bit constants
_FLAG_VENDOR    = 0x80
_FLAG_MANDATORY = 0x40
_FLAG_PROTECTED = 0x20

# Header sizes
_HDR_BASE   = 8   # code(4) + flags(1) + length(3)
_HDR_VENDOR = 4   # vendor-id


# ---------------------------------------------------------------------------
# Public AVP class
# ---------------------------------------------------------------------------

class AVP:
    """
    A single Diameter AVP.

    Parameters
    ----------
    name : str
        AVP name as it appears in the dictionary (e.g. ``"Origin-Host"``).
        When decoding an unknown AVP, the name is set to ``"Unknown-<code>"``.
    value : Any
        Python representation of the AVP value:

        ============  =============================================
        Encoding      Accepted Python types
        ============  =============================================
        bytes         ``bytes``
        utf8          ``str`` or ``bytes``
        int32/int64   ``int``
        uint32/uint64 ``int``
        float32/float64 ``float``
        enum          ``int`` (code) or ``str`` (enum name)
        address       ``str`` (dotted-quad / colon-hex) or ``bytes``
        grouped       ``list[AVP]``
        ============  =============================================

    vendor_id : int, optional
        Numeric vendor ID.  Normally inferred from the dictionary entry;
        supply this only to override.
    code : int, optional
        Numeric AVP code override (needed when *name* is unknown).
    flags : int, optional
        Raw flags byte override.  When omitted, flags are derived from the
        dictionary entry's ``mandatory`` / ``protected`` / ``vendor_bit``
        attributes.
    """

    __slots__ = ("name", "value", "_vendor_id", "_code", "_flags")

    def __init__(
        self,
        name: str,
        value: Any,
        *,
        vendor_id: Optional[int] = None,
        code: Optional[int] = None,
        flags: Optional[int] = None,
    ) -> None:
        self.name = name
        self.value = value
        self._vendor_id = vendor_id
        self._code = code
        self._flags = flags

    def __repr__(self) -> str:
        return f"AVP({self.name!r}, {self.value!r})"

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def encode(self, dictionary: "Dictionary") -> bytes:
        """
        Encode this AVP to wire bytes (including any required padding).

        Parameters
        ----------
        dictionary : Dictionary
            Loaded Diameter dictionary used to resolve type information.

        Returns
        -------
        bytes
            The AVP header + data + padding (4-byte aligned).
        """
        avp_def = dictionary.get_avp(self.name)

        if avp_def is None and self._code is None:
            raise KeyError(f"Unknown AVP and no code override: {self.name!r}")

        code = self._code if self._code is not None else avp_def.code
        encoding = avp_def.encoding if avp_def else "bytes"
        vendor_code = (
            self._vendor_id
            if self._vendor_id is not None
            else (avp_def.vendor_code if avp_def else 0)
        )

        data = _encode_value(encoding, self.value, self.name, dictionary)

        has_vendor = vendor_code != 0
        flags = self._flags if self._flags is not None else _build_flags(avp_def, has_vendor)

        hdr_size = _HDR_BASE + (_HDR_VENDOR if has_vendor else 0)
        length = hdr_size + len(data)

        header = struct.pack("!I", code) + bytes([flags]) + _pack3(length)
        if has_vendor:
            header += struct.pack("!I", vendor_code)

        pad = (4 - len(data) % 4) % 4
        return header + data + b"\x00" * pad

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------

    @classmethod
    def decode(
        cls,
        data: bytes,
        offset: int,
        dictionary: "Dictionary",
    ) -> Tuple["AVP", int]:
        """
        Decode one AVP from *data* starting at *offset*.

        Returns
        -------
        tuple[AVP, int]
            The decoded AVP and the new offset (advanced past this AVP
            including any padding bytes).
        """
        if offset + _HDR_BASE > len(data):
            raise ValueError(
                f"Truncated AVP header at offset {offset} "
                f"(only {len(data) - offset} bytes remain)"
            )

        code = struct.unpack_from("!I", data, offset)[0]
        flags = data[offset + 4]
        length = _unpack3(data, offset + 5)

        if length < _HDR_BASE:
            raise ValueError(f"Invalid AVP length {length} at offset {offset}")
        if offset + length > len(data):
            raise ValueError(
                f"AVP length {length} at offset {offset} exceeds buffer "
                f"({len(data)} bytes total)"
            )

        has_vendor = bool(flags & _FLAG_VENDOR)
        hdr_size = _HDR_BASE + (_HDR_VENDOR if has_vendor else 0)

        if has_vendor:
            if offset + hdr_size > len(data):
                raise ValueError(f"Truncated vendor-ID at offset {offset}")
            vendor_code = struct.unpack_from("!I", data, offset + _HDR_BASE)[0]
        else:
            vendor_code = 0

        value_bytes = data[offset + hdr_size: offset + length]

        avp_def = dictionary.get_avp_by_code(code, vendor_code)
        if avp_def is not None:
            name = avp_def.name
            encoding = avp_def.encoding
        else:
            name = f"Unknown-{code}"
            encoding = "bytes"

        value = _decode_value(encoding, value_bytes, name, dictionary)
        avp = cls(name, value, vendor_id=vendor_code or None, code=code, flags=flags)

        # Advance past padding
        padded_length = (length + 3) & ~3
        return avp, offset + padded_length


# ---------------------------------------------------------------------------
# Internal encode / decode helpers
# ---------------------------------------------------------------------------

def _build_flags(avp_def: Optional["AVPDef"], has_vendor: bool) -> int:
    flags = 0
    if has_vendor:
        flags |= _FLAG_VENDOR
    if avp_def and avp_def.mandatory == "must":
        flags |= _FLAG_MANDATORY
    if avp_def and avp_def.protected == "must":
        flags |= _FLAG_PROTECTED
    return flags


def _encode_value(
    encoding: str, value: Any, name: str, dictionary: "Dictionary"
) -> bytes:
    if encoding == "bytes":
        return _as_bytes(value, name)

    if encoding == "utf8":
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, bytes):
            return value
        raise TypeError(
            f"AVP {name!r}: expected str or bytes for UTF-8 encoding, "
            f"got {type(value).__name__}"
        )

    if encoding == "address":
        return _encode_address(value, name)

    if encoding == "int32":
        return struct.pack("!i", int(value))

    if encoding == "int64":
        return struct.pack("!q", int(value))

    if encoding == "uint32":
        return struct.pack("!I", int(value))

    if encoding == "uint64":
        return struct.pack("!Q", int(value))

    if encoding == "float32":
        return struct.pack("!f", float(value))

    if encoding == "float64":
        return struct.pack("!d", float(value))

    if encoding == "enum":
        if isinstance(value, str):
            avp_def = dictionary.get_avp(name)
            if avp_def is None or value not in avp_def.enums:
                raise ValueError(
                    f"AVP {name!r}: unknown enum name {value!r}"
                )
            value = avp_def.enums[value]
        return struct.pack("!i", int(value))

    if encoding == "grouped":
        if not isinstance(value, (list, tuple)):
            raise TypeError(
                f"AVP {name!r} is Grouped but value is {type(value).__name__}"
            )
        return b"".join(child.encode(dictionary) for child in value)

    # Fallback
    return _as_bytes(value, name)


def _decode_value(
    encoding: str, data: bytes, name: str, dictionary: "Dictionary"
) -> Any:
    if encoding == "bytes":
        return data

    if encoding == "utf8":
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data

    if encoding == "address":
        return _decode_address(data)

    if encoding == "int32":
        if len(data) < 4:
            return data
        return struct.unpack("!i", data[:4])[0]

    if encoding == "int64":
        if len(data) < 8:
            return data
        return struct.unpack("!q", data[:8])[0]

    if encoding == "uint32":
        if len(data) < 4:
            return data
        return struct.unpack("!I", data[:4])[0]

    if encoding == "uint64":
        if len(data) < 8:
            return data
        return struct.unpack("!Q", data[:8])[0]

    if encoding == "float32":
        if len(data) < 4:
            return data
        return struct.unpack("!f", data[:4])[0]

    if encoding == "float64":
        if len(data) < 8:
            return data
        return struct.unpack("!d", data[:8])[0]

    if encoding == "enum":
        if len(data) < 4:
            return data
        code_val = struct.unpack("!i", data[:4])[0]
        avp_def = dictionary.get_avp(name)
        if avp_def and code_val in avp_def.enum_by_code:
            return avp_def.enum_by_code[code_val]
        return code_val

    if encoding == "grouped":
        avps: List["AVP"] = []
        pos = 0
        while pos < len(data):
            child, pos = AVP.decode(data, pos, dictionary)
            avps.append(child)
        return avps

    return data


# ---------------------------------------------------------------------------
# Low-level utility functions
# ---------------------------------------------------------------------------

def _as_bytes(value: Any, name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(
        f"AVP {name!r}: cannot encode {type(value).__name__!r} as OctetString"
    )


def _encode_address(value: Any, name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        # Try IPv4 first
        try:
            packed = socket.inet_aton(value)
            return struct.pack("!H", 1) + packed  # family=1 (IPv4)
        except OSError:
            pass
        # Try IPv6
        try:
            packed = socket.inet_pton(socket.AF_INET6, value)
            return struct.pack("!H", 2) + packed  # family=2 (IPv6)
        except OSError:
            pass
        raise ValueError(
            f"AVP {name!r}: {value!r} is not a valid IPv4 or IPv6 address"
        )
    raise TypeError(
        f"AVP {name!r}: expected str or bytes for Address, got {type(value).__name__}"
    )


def _decode_address(data: bytes) -> Any:
    if len(data) < 2:
        return data
    family = struct.unpack_from("!H", data)[0]
    addr_bytes = data[2:]
    if family == 1 and len(addr_bytes) == 4:   # IPv4
        return socket.inet_ntoa(addr_bytes)
    if family == 2 and len(addr_bytes) == 16:  # IPv6
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    return data  # Unknown family: return raw bytes


def _pack3(n: int) -> bytes:
    """Pack an unsigned integer into 3 bytes, big-endian."""
    if n > 0xFFFFFF:
        raise ValueError(f"Value {n} does not fit in 3 bytes")
    return struct.pack("!I", n)[1:]


def _unpack3(data: bytes, offset: int) -> int:
    """Unpack a 3-byte big-endian unsigned integer."""
    return struct.unpack("!I", b"\x00" + data[offset: offset + 3])[0]

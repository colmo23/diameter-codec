"""
Diameter message encoding and decoding.

Wire format (RFC 6733 §3)
--------------------------
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |                 Message Length                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Command Flags |                  Command Code                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Application-ID                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Hop-by-Hop Identifier                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      End-to-End Identifier                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  AVPs ...
+-+-+-+-+-+-+-+-+

Header size: 20 bytes.

Command flags
-------------
  R (0x80) – Request
  P (0x40) – Proxiable
  E (0x20) – Error
  T (0x10) – Potentially re-transmitted message
"""

import os
import struct
from typing import List, Optional, Union, TYPE_CHECKING

from .avp import AVP, _pack3, _unpack3

if TYPE_CHECKING:
    from .dictionary import Dictionary

# Message flag bits
FLAG_REQUEST    = 0x80
FLAG_PROXIABLE  = 0x40
FLAG_ERROR      = 0x20
FLAG_RETRANSMIT = 0x10

DIAMETER_VERSION = 1
HEADER_SIZE = 20

# Simple counter for hop-by-hop and end-to-end IDs
_HBH_COUNTER = int.from_bytes(os.urandom(4), "big")
_E2E_COUNTER = int.from_bytes(os.urandom(4), "big")


def _next_hbh() -> int:
    global _HBH_COUNTER
    _HBH_COUNTER = (_HBH_COUNTER + 1) & 0xFFFFFFFF
    return _HBH_COUNTER


def _next_e2e() -> int:
    global _E2E_COUNTER
    _E2E_COUNTER = (_E2E_COUNTER + 1) & 0xFFFFFFFF
    return _E2E_COUNTER


class Message:
    """
    A Diameter protocol message.

    Parameters
    ----------
    command : str or int
        Command name (e.g. ``"Capabilities-Exchange"``) or numeric code.
        When a name is given it is resolved against the dictionary on encode.
    app_id : int
        Application-ID field (default 0 = base protocol).
    is_request : bool
        Set the R-bit (default ``True``).
    is_proxiable : bool
        Set the P-bit (default ``False``).
    is_error : bool
        Set the E-bit (default ``False``).
    is_retransmit : bool
        Set the T-bit (default ``False``).
    hop_by_hop_id : int, optional
        Hop-by-Hop Identifier.  Auto-generated if omitted.
    end_to_end_id : int, optional
        End-to-End Identifier.  Auto-generated if omitted.
    avps : list[AVP], optional
        Ordered list of AVPs to include in the message.
    """

    def __init__(
        self,
        command: Union[str, int],
        app_id: int = 0,
        *,
        is_request: bool = True,
        is_proxiable: bool = False,
        is_error: bool = False,
        is_retransmit: bool = False,
        hop_by_hop_id: Optional[int] = None,
        end_to_end_id: Optional[int] = None,
        avps: Optional[List[AVP]] = None,
    ) -> None:
        self.command = command          # str name or int code
        self.app_id = app_id
        self.is_request = is_request
        self.is_proxiable = is_proxiable
        self.is_error = is_error
        self.is_retransmit = is_retransmit
        self.hop_by_hop_id: int = hop_by_hop_id if hop_by_hop_id is not None else _next_hbh()
        self.end_to_end_id: int = end_to_end_id if end_to_end_id is not None else _next_e2e()
        self.avps: List[AVP] = list(avps) if avps else []

    def __repr__(self) -> str:
        flag_str = "".join([
            "R" if self.is_request else "",
            "P" if self.is_proxiable else "",
            "E" if self.is_error else "",
            "T" if self.is_retransmit else "",
        ])
        avp_lines = "".join(f"\n  {avp!r}," for avp in self.avps)
        return (
            f"Message(command={self.command!r}, app_id={self.app_id}, "
            f"flags={flag_str!r}, avps=[{avp_lines}\n])"
        )

    # ------------------------------------------------------------------
    # AVP helpers
    # ------------------------------------------------------------------

    def get_avp(self, name: str) -> Optional[AVP]:
        """Return the first AVP with the given name, or ``None``."""
        for avp in self.avps:
            if avp.name == name:
                return avp
        return None

    def get_avps(self, name: str) -> List[AVP]:
        """Return all AVPs with the given name."""
        return [avp for avp in self.avps if avp.name == name]

    def add_avp(self, avp: AVP) -> None:
        """Append *avp* to the message."""
        self.avps.append(avp)

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def encode(self, dictionary: "Dictionary") -> bytes:
        """
        Encode this message to wire bytes.

        Parameters
        ----------
        dictionary : Dictionary

        Returns
        -------
        bytes
        """
        # Resolve command code
        if isinstance(self.command, int):
            command_code = self.command
        else:
            cmd_def = dictionary.get_command(self.command)
            if cmd_def is None:
                raise KeyError(f"Unknown command: {self.command!r}")
            command_code = cmd_def.code

        # Encode all AVPs
        avp_bytes = b"".join(avp.encode(dictionary) for avp in self.avps)

        # Build flags byte
        flags = 0
        if self.is_request:
            flags |= FLAG_REQUEST
        if self.is_proxiable:
            flags |= FLAG_PROXIABLE
        if self.is_error:
            flags |= FLAG_ERROR
        if self.is_retransmit:
            flags |= FLAG_RETRANSMIT

        length = HEADER_SIZE + len(avp_bytes)
        header = (
            bytes([DIAMETER_VERSION])
            + _pack3(length)
            + bytes([flags])
            + _pack3(command_code)
            + struct.pack("!I", self.app_id)
            + struct.pack("!I", self.hop_by_hop_id)
            + struct.pack("!I", self.end_to_end_id)
        )
        return header + avp_bytes

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------

    @classmethod
    def decode(cls, data: bytes, dictionary: "Dictionary") -> "Message":
        """
        Decode a Diameter message from wire bytes.

        Parameters
        ----------
        data : bytes
            Raw bytes starting at the first byte of the Diameter header.
        dictionary : Dictionary

        Returns
        -------
        Message
        """
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"Too short to be a Diameter message: {len(data)} bytes"
            )

        version = data[0]
        if version != DIAMETER_VERSION:
            raise ValueError(f"Unexpected Diameter version: {version}")

        length = _unpack3(data, 1)
        if length < HEADER_SIZE:
            raise ValueError(f"Invalid message length: {length}")
        if length > len(data):
            raise ValueError(
                f"Message length {length} exceeds buffer ({len(data)} bytes)"
            )

        flags = data[4]
        command_code = _unpack3(data, 5)
        app_id = struct.unpack_from("!I", data, 8)[0]
        hbh = struct.unpack_from("!I", data, 12)[0]
        e2e = struct.unpack_from("!I", data, 16)[0]

        is_request    = bool(flags & FLAG_REQUEST)
        is_proxiable  = bool(flags & FLAG_PROXIABLE)
        is_error      = bool(flags & FLAG_ERROR)
        is_retransmit = bool(flags & FLAG_RETRANSMIT)

        # Resolve command name
        cmd_def = dictionary.get_command_by_code(command_code)
        command: Union[str, int] = cmd_def.name if cmd_def else command_code

        # Decode AVPs
        avps: List[AVP] = []
        offset = HEADER_SIZE
        end = length  # use the message length, not buffer length
        while offset < end:
            avp, offset = AVP.decode(data, offset, dictionary)
            avps.append(avp)

        return cls(
            command=command,
            app_id=app_id,
            is_request=is_request,
            is_proxiable=is_proxiable,
            is_error=is_error,
            is_retransmit=is_retransmit,
            hop_by_hop_id=hbh,
            end_to_end_id=e2e,
            avps=avps,
        )

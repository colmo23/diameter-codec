"""
3GPP Diameter message factories (TS 29.272, 29.229, 29.329, 29.214, 29.212).

Each public function builds a ready-to-encode :class:`~diameter.message.Message`
with sensible default AVP values.  Every parameter can be overridden; pass
``extra_avps`` to append additional AVPs not covered by the function signature.

Interfaces covered
------------------
* **S6a / S6d** (App-ID 16777251, RFC 5516 / TS 29.272) — MME/SGSN ↔ HSS
  ULR/ULA, CLR/CLA, AIR/AIA, IDR/IDA, DSR/DSA, PUR/PUA, RSR/RSA, NOR/NOA
* **Cx** (App-ID 16777216, TS 29.229) — S-CSCF / I-CSCF ↔ HSS
  UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, RTR/RTA, PPR/PPA
* **Sh** (App-ID 16777217, TS 29.329) — AS / MRFC ↔ HSS
  UDR/UDA, PUR/PUA, SNR/SNA, PNR/PNA
* **Rx** (App-ID 16777236, TS 29.214) — AF ↔ PCRF
  AAR/AAA, STR/STA, RAR/RAA, ASR/ASA
* **Gx** (App-ID 16777238, TS 29.212) — PCEF ↔ PCRF
  CCR/CCA, RAR/RAA
"""

import os
import time
import random
from typing import List, Optional

from .avp import AVP
from .message import Message

# ---------------------------------------------------------------------------
# Application IDs
# ---------------------------------------------------------------------------
APP_CX  = 16777216   # Cx/Dx  TS 29.229
APP_SH  = 16777217   # Sh/Dh  TS 29.329
APP_RX  = 16777236   # Rx     TS 29.214
APP_GX  = 16777238   # Gx     TS 29.212
APP_S6A = 16777251   # S6a/S6d RFC 5516 / TS 29.272
APP_S13 = 16777252   # S13    TS 29.272

# ---------------------------------------------------------------------------
# Vendor ID
# ---------------------------------------------------------------------------
VENDOR_3GPP = 10415

# ---------------------------------------------------------------------------
# Common result codes (Diameter base, RFC 6733 §7.1.1)
# ---------------------------------------------------------------------------
SUCCESS                  = 2001
LIMITED_SUCCESS          = 2002
AUTHENTICATION_REJECTED  = 4001
UNABLE_TO_COMPLY         = 5012

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _sid(origin_host: str) -> str:
    """Generate a Diameter Session-Id in standard format."""
    ts = int(time.time())
    rand = random.randint(0, 0xFFFFFFFF)
    return f"{origin_host};{ts};{rand}"


def _vsai(app_id: int) -> AVP:
    """Build a Vendor-Specific-Application-Id grouped AVP."""
    return AVP("Vendor-Specific-Application-Id", [
        AVP("Vendor-Id", VENDOR_3GPP),
        AVP("Auth-Application-Id", app_id),
    ])


def _exp_result(code: int) -> AVP:
    """Build an Experimental-Result grouped AVP."""
    return AVP("Experimental-Result", [
        AVP("Vendor-Id", VENDOR_3GPP),
        AVP("Experimental-Result-Code", code),
    ])


def _base_request(
    command: str,
    app_id: int,
    origin_host: str,
    origin_realm: str,
    destination_host: Optional[str],
    destination_realm: str,
    session_id: Optional[str],
    proxiable: bool = True,
) -> List[AVP]:
    """Return the AVP list common to most 3GPP requests."""
    sid = session_id or _sid(origin_host)
    avps = [
        AVP("Session-Id", sid),
        _vsai(app_id),
        AVP("Auth-Session-State", "NO_STATE_MAINTAINED"),
        AVP("Origin-Host", origin_host),
        AVP("Origin-Realm", origin_realm),
    ]
    if destination_host:
        avps.append(AVP("Destination-Host", destination_host))
    avps.append(AVP("Destination-Realm", destination_realm))
    return avps


def _base_answer(
    command: str,
    app_id: int,
    origin_host: str,
    origin_realm: str,
    session_id: str,
    result_code: int,
) -> List[AVP]:
    """Return the AVP list common to most 3GPP answers."""
    return [
        AVP("Session-Id", session_id),
        _vsai(app_id),
        AVP("Auth-Session-State", "NO_STATE_MAINTAINED"),
        AVP("Origin-Host", origin_host),
        AVP("Origin-Realm", origin_realm),
        AVP("Result-Code", result_code),
    ]


# ===========================================================================
# S6a / S6d  —  MME/SGSN ↔ HSS  (RFC 5516 / TS 29.272)
# ===========================================================================

# ---------------------------------------------------------------------------
# Update-Location  (ULR / ULA)  — code 316
# ---------------------------------------------------------------------------

def ulr(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    user_name: str = "001010123456789",
    rat_type: str = "EUTRAN",
    ulr_flags: int = 0x02,
    visited_plmn_id: bytes = b"\x00\xf1\x10",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Update-Location-Request (ULR)  TS 29.272 §7.2.3.

    Sent by the MME (or SGSN) to the HSS to register the user's location.

    Parameters
    ----------
    user_name : str
        IMSI (e.g. ``"001010123456789"``).
    rat_type : str
        Radio-Access-Technology type enum name (e.g. ``"EUTRAN"``, ``"UTRAN"``).
    ulr_flags : int
        Bitmask of ULR-Flags (default 0x02 = S6a/S6d-Indicator).
    visited_plmn_id : bytes
        3-byte encoded Visited-PLMN-Id.
    """
    avps = _base_request("3GPP-Update-Location", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Name", user_name),
        AVP("RAT-Type", rat_type),
        AVP("ULR-Flags", ulr_flags),
        AVP("Visited-PLMN-Id", visited_plmn_id),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Update-Location", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def ula(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    ula_flags: int = 0x01,
    subscription_data_avps: Optional[List[AVP]] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Update-Location-Answer (ULA)  TS 29.272 §7.2.4.

    Parameters
    ----------
    ula_flags : int
        Bitmask of ULA-Flags (default 0x01 = EPS-Subscriptions-Present).
    subscription_data_avps : list[AVP], optional
        Child AVPs inside the Subscription-Data grouped AVP.  A minimal
        placeholder is added when omitted.
    """
    avps = _base_answer("3GPP-Update-Location", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("ULA-Flags", ula_flags))
    sub_children = subscription_data_avps or [
        AVP("MSISDN", b"\x91\x10\x32\x54\x76\x98"),   # BCD-encoded
        AVP("Access-Restriction-Data", 0),
        AVP("Subscriber-Status", 0),                    # 0 = SERVICE_GRANTED
        AVP("Network-Access-Mode", 2),                  # 2 = ONLY_PACKET
    ]
    avps.append(AVP("Subscription-Data", sub_children))
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Update-Location", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Cancel-Location  (CLR / CLA)  — code 317
# ---------------------------------------------------------------------------

def clr(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "mme.example.com",
    destination_realm: str = "example.com",
    user_name: str = "001010123456789",
    cancellation_type: str = "SUBSCRIPTION_WITHDRAWAL",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Cancel-Location-Request (CLR)  TS 29.272 §7.2.7.

    Sent by the HSS to the MME/SGSN to cancel a subscriber's registration.

    Parameters
    ----------
    cancellation_type : str
        Enum name (e.g. ``"SUBSCRIPTION_WITHDRAWAL"``, ``"MME_UPDATE_PROCEDURE"``).
    """
    avps = _base_request("3GPP-Cancel-Location", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Name", user_name),
        AVP("Cancellation-Type", cancellation_type),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Cancel-Location", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def cla(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Cancel-Location-Answer (CLA)  TS 29.272 §7.2.8."""
    avps = _base_answer("3GPP-Cancel-Location", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Cancel-Location", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Authentication-Information  (AIR / AIA)  — code 318
# ---------------------------------------------------------------------------

def air(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    user_name: str = "001010123456789",
    visited_plmn_id: bytes = b"\x00\xf1\x10",
    num_vectors: int = 1,
    immediate_response: int = 0,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Authentication-Information-Request (AIR)  TS 29.272 §7.2.5.

    Parameters
    ----------
    num_vectors : int
        Number of E-UTRAN authentication vectors requested.
    immediate_response : int
        Immediate-Response-Preferred flag (0 = off).
    """
    avps = _base_request("3GPP-Authentication-Information", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Name", user_name),
        AVP("Visited-PLMN-Id", visited_plmn_id),
        AVP("Requested-EUTRAN-Authentication-Info", [
            AVP("Number-Of-Requested-Vectors", num_vectors),
            AVP("Immediate-Response-Preferred", immediate_response),
        ]),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Authentication-Information", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def aia(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    rand: bytes = b"\x00" * 16,
    xres: bytes = b"\x00" * 8,
    autn: bytes = b"\x00" * 16,
    kasme: bytes = b"\x00" * 32,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Authentication-Information-Answer (AIA)  TS 29.272 §7.2.6.

    Parameters
    ----------
    rand, xres, autn, kasme : bytes
        Authentication vector components.  Defaults are all-zero placeholders.
    """
    avps = _base_answer("3GPP-Authentication-Information", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("Authentication-Info", [
        AVP("E-UTRAN-Vector", [
            AVP("RAND", rand),
            AVP("XRES", xres),
            AVP("AUTN", autn),
            AVP("KASME", kasme),
        ]),
    ]))
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Authentication-Information", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Insert-Subscriber-Data  (IDR / IDA)  — code 319
# ---------------------------------------------------------------------------

def idr(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "mme.example.com",
    destination_realm: str = "example.com",
    user_name: str = "001010123456789",
    idr_flags: int = 0,
    subscription_data_avps: Optional[List[AVP]] = None,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Insert-Subscriber-Data-Request (IDR)  TS 29.272 §7.2.9.

    Sent by the HSS to the MME/SGSN to insert or update subscription data.
    """
    avps = _base_request("3GPP-Insert-Subscriber-Data", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Name", user_name),
        AVP("IDR-Flags", idr_flags),
    ]
    sub_children = subscription_data_avps or [
        AVP("MSISDN", b"\x91\x10\x32\x54\x76\x98"),
        AVP("Subscriber-Status", 0),
        AVP("Network-Access-Mode", 2),
    ]
    avps.append(AVP("Subscription-Data", sub_children))
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Insert-Subscriber-Data", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def ida(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    ida_flags: int = 0,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Insert-Subscriber-Data-Answer (IDA)  TS 29.272 §7.2.10."""
    avps = _base_answer("3GPP-Insert-Subscriber-Data", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("IDA-Flags", ida_flags))
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Insert-Subscriber-Data", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Delete-Subscriber-Data  (DSR / DSA)  — code 320
# ---------------------------------------------------------------------------

def dsr(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "mme.example.com",
    destination_realm: str = "example.com",
    user_name: str = "001010123456789",
    dsr_flags: int = 0,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Delete-Subscriber-Data-Request (DSR)  TS 29.272 §7.2.11.

    Parameters
    ----------
    dsr_flags : int
        Bitmask of DSR-Flags indicating which data to delete.
    """
    avps = _base_request("3GPP-Delete-Subscriber-Data", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Name", user_name),
        AVP("DSR-Flags", dsr_flags),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Delete-Subscriber-Data", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def dsa(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    dsa_flags: int = 0,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Delete-Subscriber-Data-Answer (DSA)  TS 29.272 §7.2.12."""
    avps = _base_answer("3GPP-Delete-Subscriber-Data", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("DSA-Flags", dsa_flags))
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Delete-Subscriber-Data", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Purge-UE  (PUR / PUA)  — code 321
# ---------------------------------------------------------------------------

def pur_s6a(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    user_name: str = "001010123456789",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Purge-UE-Request (PUR)  TS 29.272 §7.2.13.

    Sent by the MME/SGSN to notify the HSS that a subscriber has detached.
    """
    avps = _base_request("3GPP-Purge-UE", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("User-Name", user_name))
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Purge-UE", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def pua_s6a(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    pua_flags: int = 0,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Purge-UE-Answer (PUA)  TS 29.272 §7.2.14."""
    avps = _base_answer("3GPP-Purge-UE", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("PUA-Flags", pua_flags))
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Purge-UE", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Reset  (RSR / RSA)  — code 322
# ---------------------------------------------------------------------------

def rsr_s6a(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "mme.example.com",
    destination_realm: str = "example.com",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Reset-Request (RSR)  TS 29.272 §7.2.15.

    Sent by the HSS to the MME/SGSN to trigger a re-registration of all users.
    """
    avps = _base_request("3GPP-Reset", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Reset", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def rsa_s6a(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Reset-Answer (RSA)  TS 29.272 §7.2.16."""
    avps = _base_answer("3GPP-Reset", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Reset", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Notify  (NOR / NOA)  — code 323
# ---------------------------------------------------------------------------

def nor(
    origin_host: str = "mme.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    user_name: str = "001010123456789",
    nor_flags: int = 0,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Notify-Request (NOR)  TS 29.272 §7.2.17.

    Sent by the MME/SGSN to notify the HSS of an event (e.g. S6a/S6d RAT change).

    Parameters
    ----------
    nor_flags : int
        Bitmask of NOR-Flags.
    """
    avps = _base_request("3GPP-Notify", APP_S6A,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Name", user_name),
        AVP("NOR-Flags", nor_flags),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Notify", APP_S6A, is_request=True,
                   is_proxiable=True, avps=avps)


def noa(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Notify-Answer (NOA)  TS 29.272 §7.2.18."""
    avps = _base_answer("3GPP-Notify", APP_S6A,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("3GPP-Notify", APP_S6A, is_request=False,
                   is_proxiable=True, avps=avps)


# ===========================================================================
# Cx  —  S-CSCF / I-CSCF ↔ HSS  (TS 29.229)
# ===========================================================================

# ---------------------------------------------------------------------------
# User-Authorization  (UAR / UAA)  — code 300
# ---------------------------------------------------------------------------

def uar(
    origin_host: str = "icscf.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    public_identity: str = "sip:alice@example.com",
    visited_network_id: str = "example.com",
    user_authorization_type: str = "REGISTRATION",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    User-Authorization-Request (UAR)  TS 29.229 §6.1.1.

    Sent by the I-CSCF to the HSS during SIP REGISTER to authorize the user
    and determine which S-CSCF should serve them.

    Parameters
    ----------
    user_authorization_type : str
        ``"REGISTRATION"``, ``"DE_REGISTRATION"``, or
        ``"REGISTRATION_AND_CAPABILITIES"``.
    """
    avps = _base_request("User-Authorization", APP_CX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("Public-Identity", public_identity),
        AVP("Visited-Network-Identifier", visited_network_id.encode()),
        AVP("User-Authorization-Type", user_authorization_type),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("User-Authorization", APP_CX, is_request=True,
                   is_proxiable=True, avps=avps)


def uaa(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    server_name: str = "sip:scscf.example.com:5060",
    server_capabilities_avps: Optional[List[AVP]] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    User-Authorization-Answer (UAA)  TS 29.229 §6.1.2.

    Parameters
    ----------
    server_name : str
        SIP URI of the assigned S-CSCF.
    server_capabilities_avps : list[AVP], optional
        Child AVPs of Server-Capabilities grouped AVP.
    """
    avps = _base_answer("User-Authorization", APP_CX,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("Server-Name", server_name))
    if server_capabilities_avps:
        avps.append(AVP("Server-Capabilities", server_capabilities_avps))
    if extra_avps:
        avps += extra_avps
    return Message("User-Authorization", APP_CX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Server-Assignment  (SAR / SAA)  — code 301
# ---------------------------------------------------------------------------

def sar(
    origin_host: str = "scscf.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    public_identity: str = "sip:alice@example.com",
    server_name: str = "sip:scscf.example.com:5060",
    server_assignment_type: str = "REGISTRATION",
    user_data_already_available: int = 0,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Server-Assignment-Request (SAR)  TS 29.229 §6.1.3.

    Sent by the S-CSCF to the HSS after completing a SIP registration.

    Parameters
    ----------
    server_assignment_type : str
        Assignment type enum name (e.g. ``"REGISTRATION"``,
        ``"RE_REGISTRATION"``, ``"USER_DEREGISTRATION"``).
    user_data_already_available : int
        0 = USER_DATA_NOT_AVAILABLE, 1 = USER_DATA_ALREADY_AVAILABLE.
    """
    avps = _base_request("Server-Assignment", APP_CX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("Public-Identity", public_identity),
        AVP("Server-Name", server_name),
        AVP("Server-Assignment-Type", server_assignment_type),
        AVP("User-Data-Already-Available", user_data_already_available),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("Server-Assignment", APP_CX, is_request=True,
                   is_proxiable=True, avps=avps)


def saa(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    user_data: bytes = b"",
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Server-Assignment-Answer (SAA)  TS 29.229 §6.1.4.

    Parameters
    ----------
    user_data : bytes
        Raw IMS Subscription XML (Cx-User-Data AVP value).
    """
    avps = _base_answer("Server-Assignment", APP_CX,
                        origin_host, origin_realm, session_id, result_code)
    if user_data:
        avps.append(AVP("Cx-User-Data", user_data))
    if extra_avps:
        avps += extra_avps
    return Message("Server-Assignment", APP_CX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Location-Info  (LIR / LIA)  — code 302
# ---------------------------------------------------------------------------

def lir(
    origin_host: str = "icscf.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    public_identity: str = "sip:alice@example.com",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Location-Info-Request (LIR)  TS 29.229 §6.1.5.

    Sent by the I-CSCF to the HSS to find the S-CSCF serving a user.
    """
    avps = _base_request("Location-Info", APP_CX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("Public-Identity", public_identity))
    if extra_avps:
        avps += extra_avps
    return Message("Location-Info", APP_CX, is_request=True,
                   is_proxiable=True, avps=avps)


def lia(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    server_name: str = "sip:scscf.example.com:5060",
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Location-Info-Answer (LIA)  TS 29.229 §6.1.6."""
    avps = _base_answer("Location-Info", APP_CX,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("Server-Name", server_name))
    if extra_avps:
        avps += extra_avps
    return Message("Location-Info", APP_CX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Multimedia-Auth  (MAR / MAA)  — code 303
# ---------------------------------------------------------------------------

def mar(
    origin_host: str = "scscf.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    public_identity: str = "sip:alice@example.com",
    server_name: str = "sip:scscf.example.com:5060",
    sip_auth_data_item_avps: Optional[List[AVP]] = None,
    sip_number_auth_items: int = 1,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Multimedia-Auth-Request (MAR)  TS 29.229 §6.1.7.

    Sent by the S-CSCF to the HSS to authenticate an IMS subscriber.
    """
    avps = _base_request("Multimedia-Auth", APP_CX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    auth_item_avps = sip_auth_data_item_avps or [
        AVP("SIP-Authentication-Scheme", "DIGEST"),
    ]
    avps += [
        AVP("Public-Identity", public_identity),
        AVP("Server-Name", server_name),
        AVP("SIP-Number-Auth-Items", sip_number_auth_items),
        AVP("SIP-Auth-Data-Item", auth_item_avps),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("Multimedia-Auth", APP_CX, is_request=True,
                   is_proxiable=True, avps=avps)


def maa(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    public_identity: str = "sip:alice@example.com",
    sip_number_auth_items: int = 1,
    sip_auth_data_item_avps: Optional[List[AVP]] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Multimedia-Auth-Answer (MAA)  TS 29.229 §6.1.8.

    Parameters
    ----------
    sip_auth_data_item_avps : list[AVP], optional
        Child AVPs of SIP-Auth-Data-Item (RAND, AUTN, etc.).
    """
    avps = _base_answer("Multimedia-Auth", APP_CX,
                        origin_host, origin_realm, session_id, result_code)
    avps.append(AVP("Public-Identity", public_identity))
    avps.append(AVP("SIP-Number-Auth-Items", sip_number_auth_items))
    auth_item_avps = sip_auth_data_item_avps or [
        AVP("SIP-Authentication-Scheme", "DIGEST"),
        AVP("SIP-Item-Number", 1),
        AVP("SIP-Authenticate", [
            AVP("Confidentiality-Key", b"\x00" * 16),
            AVP("Integrity-Key", b"\x00" * 16),
        ]),
    ]
    avps.append(AVP("SIP-Auth-Data-Item", auth_item_avps))
    if extra_avps:
        avps += extra_avps
    return Message("Multimedia-Auth", APP_CX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Registration-Termination  (RTR / RTA)  — code 304
# ---------------------------------------------------------------------------

def rtr(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "scscf.example.com",
    destination_realm: str = "example.com",
    public_identity: str = "sip:alice@example.com",
    deregistration_reason: str = "PERMANENT_TERMINATION",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Registration-Termination-Request (RTR)  TS 29.229 §6.1.9.

    Sent by the HSS to the S-CSCF to terminate a user's IMS registration.

    Parameters
    ----------
    deregistration_reason : str
        Reason-Code enum name (``"PERMANENT_TERMINATION"``,
        ``"NEW_SERVER_ASSIGNED"``, ``"SERVER_CHANGE"``, ``"REMOVE_S-CSCF"``).
    """
    avps = _base_request("Registration-Termination", APP_CX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("Public-Identity", public_identity),
        AVP("Deregistration-Reason", [
            AVP("Reason-Code", deregistration_reason),
        ]),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("Registration-Termination", APP_CX, is_request=True,
                   is_proxiable=True, avps=avps)


def rta(
    origin_host: str = "scscf.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Registration-Termination-Answer (RTA)  TS 29.229 §6.1.10."""
    avps = _base_answer("Registration-Termination", APP_CX,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Registration-Termination", APP_CX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Push-Profile  (PPR / PPA)  — code 305
# ---------------------------------------------------------------------------

def ppr(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "scscf.example.com",
    destination_realm: str = "example.com",
    public_identity: str = "sip:alice@example.com",
    user_data: bytes = b"",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Push-Profile-Request (PPR)  TS 29.229 §6.1.11.

    Sent by the HSS to push an updated user profile to the S-CSCF.
    """
    avps = _base_request("Push-Profile", APP_CX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("Public-Identity", public_identity))
    if user_data:
        avps.append(AVP("Cx-User-Data", user_data))
    if extra_avps:
        avps += extra_avps
    return Message("Push-Profile", APP_CX, is_request=True,
                   is_proxiable=True, avps=avps)


def ppa(
    origin_host: str = "scscf.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Push-Profile-Answer (PPA)  TS 29.229 §6.1.12."""
    avps = _base_answer("Push-Profile", APP_CX,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Push-Profile", APP_CX, is_request=False,
                   is_proxiable=True, avps=avps)


# ===========================================================================
# Sh  —  AS / MRFC ↔ HSS  (TS 29.329)
# ===========================================================================

# ---------------------------------------------------------------------------
# User-Data  (UDR / UDA)  — code 306
# ---------------------------------------------------------------------------

def udr(
    origin_host: str = "as.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    user_identity: str = "sip:alice@example.com",
    data_reference: str = "RepositoryData",
    service_indication: Optional[str] = None,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    User-Data-Request (UDR)  TS 29.329 §6.1.1.

    Sent by the AS to the HSS to retrieve a user's Sh profile data.

    Parameters
    ----------
    user_identity : str
        Public user identity (SIP URI or TEL URI).
    data_reference : str
        Data-Reference enum name (e.g. ``"RepositoryData"``,
        ``"IMSUserState"``, ``"S-CSCFName"``).
    service_indication : str, optional
        Service-Indication for repository data; required when
        data_reference is ``"RepositoryData"``.
    """
    avps = _base_request("User-Data", APP_SH,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Identity", [AVP("Public-Identity", user_identity)]),
        AVP("Data-Reference", data_reference),
    ]
    if service_indication is not None:
        avps.append(AVP("Service-Indication", service_indication))
    if extra_avps:
        avps += extra_avps
    return Message("User-Data", APP_SH, is_request=True,
                   is_proxiable=True, avps=avps)


def uda(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    sh_user_data: bytes = b"",
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    User-Data-Answer (UDA)  TS 29.329 §6.1.2.

    Parameters
    ----------
    sh_user_data : bytes
        Raw Sh-User-Data XML document.
    """
    avps = _base_answer("User-Data", APP_SH,
                        origin_host, origin_realm, session_id, result_code)
    if sh_user_data:
        avps.append(AVP("Sh-User-Data", sh_user_data))
    if extra_avps:
        avps += extra_avps
    return Message("User-Data", APP_SH, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Profile-Update  (PUR / PUA)  — code 307
# ---------------------------------------------------------------------------

def pur_sh(
    origin_host: str = "as.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    user_identity: str = "sip:alice@example.com",
    data_reference: str = "RepositoryData",
    sh_user_data: bytes = b"",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Profile-Update-Request (PUR)  TS 29.329 §6.1.3.

    Sent by the AS to the HSS to update a user's Sh profile data.
    """
    avps = _base_request("Profile-Update", APP_SH,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Identity", [AVP("Public-Identity", user_identity)]),
        AVP("Data-Reference", data_reference),
    ]
    if sh_user_data:
        avps.append(AVP("Sh-User-Data", sh_user_data))
    if extra_avps:
        avps += extra_avps
    return Message("Profile-Update", APP_SH, is_request=True,
                   is_proxiable=True, avps=avps)


def pua_sh(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Profile-Update-Answer (PUA)  TS 29.329 §6.1.4."""
    avps = _base_answer("Profile-Update", APP_SH,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Profile-Update", APP_SH, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Subscribe-Notifications  (SNR / SNA)  — code 308
# ---------------------------------------------------------------------------

def snr(
    origin_host: str = "as.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "hss.example.com",
    destination_realm: str = "example.com",
    user_identity: str = "sip:alice@example.com",
    data_reference: str = "IMSUserState",
    subs_req_type: str = "Subscribe",
    expiry_time: int = 3600,
    send_data_indication: int = 0,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Subscribe-Notifications-Request (SNR)  TS 29.329 §6.1.5.

    Sent by the AS to subscribe to notifications about a user's Sh data.

    Parameters
    ----------
    subs_req_type : str
        ``"Subscribe"`` or ``"Unsubscribe"``.
    expiry_time : int
        Subscription lifetime in seconds (0 = no expiry).
    send_data_indication : int
        1 = send current data with the SNA.
    """
    avps = _base_request("Subscribe-Notifications", APP_SH,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps += [
        AVP("User-Identity", [AVP("Public-Identity", user_identity)]),
        AVP("Data-Reference", data_reference),
        AVP("Subs-Req-Type", subs_req_type),
        AVP("Expiry-Time", expiry_time),
        AVP("Send-Data-Indication", send_data_indication),
    ]
    if extra_avps:
        avps += extra_avps
    return Message("Subscribe-Notifications", APP_SH, is_request=True,
                   is_proxiable=True, avps=avps)


def sna(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    expiry_time: Optional[int] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Subscribe-Notifications-Answer (SNA)  TS 29.329 §6.1.6."""
    avps = _base_answer("Subscribe-Notifications", APP_SH,
                        origin_host, origin_realm, session_id, result_code)
    if expiry_time is not None:
        avps.append(AVP("Expiry-Time", expiry_time))
    if extra_avps:
        avps += extra_avps
    return Message("Subscribe-Notifications", APP_SH, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Push-Notification  (PNR / PNA)  — code 309
# ---------------------------------------------------------------------------

def pnr(
    origin_host: str = "hss.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "as.example.com",
    destination_realm: str = "example.com",
    user_identity: str = "sip:alice@example.com",
    sh_user_data: bytes = b"",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Push-Notification-Request (PNR)  TS 29.329 §6.1.7.

    Sent by the HSS to push updated profile data to a subscribed AS.
    """
    avps = _base_request("Push-Notification", APP_SH,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("User-Identity", [AVP("Public-Identity", user_identity)]))
    if sh_user_data:
        avps.append(AVP("Sh-User-Data", sh_user_data))
    if extra_avps:
        avps += extra_avps
    return Message("Push-Notification", APP_SH, is_request=True,
                   is_proxiable=True, avps=avps)


def pna(
    origin_host: str = "as.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Push-Notification-Answer (PNA)  TS 29.329 §6.1.8."""
    avps = _base_answer("Push-Notification", APP_SH,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Push-Notification", APP_SH, is_request=False,
                   is_proxiable=True, avps=avps)


# ===========================================================================
# Rx  —  AF ↔ PCRF  (TS 29.214)
# ===========================================================================

# ---------------------------------------------------------------------------
# AA (Authorization Authentication)  (AAR / AAA)  — code 265
# ---------------------------------------------------------------------------

def aar_rx(
    origin_host: str = "af.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "pcrf.example.com",
    destination_realm: str = "example.com",
    af_application_identifier: str = "IMS",
    media_component_avps: Optional[List[AVP]] = None,
    specific_action: Optional[str] = None,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    AA-Request (AAR)  TS 29.214 §4.4.2  [Rx interface].

    Sent by the AF to the PCRF to authorize media resources for an IMS session.

    Parameters
    ----------
    af_application_identifier : str
        Application identifier string (e.g. ``"IMS"``).
    media_component_avps : list[AVP], optional
        List of Media-Component-Description grouped AVPs.  A default
        audio component is included when omitted.
    specific_action : str, optional
        Specific-Action enum for event subscriptions.
    """
    avps = _base_request("AA", APP_RX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("AF-Application-Identifier",
                    af_application_identifier.encode()))

    media_avps = media_component_avps or [
        AVP("Media-Component-Description", [
            AVP("Media-Component-Number", 1),
            AVP("Media-Sub-Component", [
                AVP("Flow-Number", 1),
                AVP("Flow-Description",
                    "permit out 17 from 198.51.100.1 20000 to 198.51.100.2 30000"),
                AVP("Flow-Description",
                    "permit in 17 from 198.51.100.2 30000 to 198.51.100.1 20000"),
                AVP("Flow-Usage", "NO_INFORMATION"),
            ]),
            AVP("Media-Type", "AUDIO"),
            AVP("Max-Requested-Bandwidth-UL", 64000),
            AVP("Max-Requested-Bandwidth-DL", 64000),
        ]),
    ]
    avps += media_avps

    if specific_action is not None:
        avps.append(AVP("Specific-Action", specific_action))
    if extra_avps:
        avps += extra_avps
    return Message("AA", APP_RX, is_request=True, is_proxiable=True, avps=avps)


def aaa_rx(
    origin_host: str = "pcrf.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    access_network_charging_address: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    AA-Answer (AAA)  TS 29.214 §4.4.3  [Rx interface].

    Parameters
    ----------
    access_network_charging_address : str, optional
        IP address of the charging node.
    """
    avps = _base_answer("AA", APP_RX,
                        origin_host, origin_realm, session_id, result_code)
    if access_network_charging_address:
        avps.append(AVP("Access-Network-Charging-Address",
                        access_network_charging_address))
    if extra_avps:
        avps += extra_avps
    return Message("AA", APP_RX, is_request=False, is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Session-Termination  (STR / STA)  — code 275
# ---------------------------------------------------------------------------

def str_rx(
    origin_host: str = "af.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "pcrf.example.com",
    destination_realm: str = "example.com",
    termination_cause: int = 1,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Session-Termination-Request (STR)  TS 29.214 §4.4.4  [Rx interface].

    Sent by the AF when an IMS session ends.

    Parameters
    ----------
    termination_cause : int
        Termination-Cause code (1 = DIAMETER_LOGOUT).
    """
    avps = _base_request("Session-Termination", APP_RX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("Termination-Cause", termination_cause))
    if extra_avps:
        avps += extra_avps
    return Message("Session-Termination", APP_RX, is_request=True,
                   is_proxiable=True, avps=avps)


def sta_rx(
    origin_host: str = "pcrf.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Session-Termination-Answer (STA)  TS 29.214 §4.4.5  [Rx interface]."""
    avps = _base_answer("Session-Termination", APP_RX,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Session-Termination", APP_RX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Re-Auth  (RAR / RAA)  — code 258  [Rx interface, PCRF→AF]
# ---------------------------------------------------------------------------

def rar_rx(
    origin_host: str = "pcrf.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "af.example.com",
    destination_realm: str = "example.com",
    specific_action: str = "CHARGING_CORRELATION_EXCHANGE",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Re-Auth-Request (RAR)  TS 29.214 §4.4.6  [Rx interface].

    Sent by the PCRF to the AF to trigger a re-authorization or to
    report a bearer event.

    Parameters
    ----------
    specific_action : str
        Specific-Action enum name describing the event.
    """
    avps = _base_request("Re-Auth", APP_RX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("Specific-Action", specific_action))
    if extra_avps:
        avps += extra_avps
    return Message("Re-Auth", APP_RX, is_request=True,
                   is_proxiable=True, avps=avps)


def raa_rx(
    origin_host: str = "af.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Re-Auth-Answer (RAA)  TS 29.214 §4.4.7  [Rx interface]."""
    avps = _base_answer("Re-Auth", APP_RX,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Re-Auth", APP_RX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Abort-Session  (ASR / ASA)  — code 274  [Rx interface, PCRF→AF]
# ---------------------------------------------------------------------------

def asr_rx(
    origin_host: str = "pcrf.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "af.example.com",
    destination_realm: str = "example.com",
    abort_cause: str = "BEARER_RELEASED",
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Abort-Session-Request (ASR)  TS 29.214 §4.4.8  [Rx interface].

    Sent by the PCRF to the AF to abort an Rx session.

    Parameters
    ----------
    abort_cause : str
        Abort-Cause enum name (e.g. ``"BEARER_RELEASED"``,
        ``"INSUFFICIENT_SERVER_RESOURCES"``).
    """
    avps = _base_request("Abort-Session", APP_RX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("Abort-Cause", abort_cause))
    if extra_avps:
        avps += extra_avps
    return Message("Abort-Session", APP_RX, is_request=True,
                   is_proxiable=True, avps=avps)


def asa_rx(
    origin_host: str = "af.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Abort-Session-Answer (ASA)  TS 29.214 §4.4.9  [Rx interface]."""
    avps = _base_answer("Abort-Session", APP_RX,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Abort-Session", APP_RX, is_request=False,
                   is_proxiable=True, avps=avps)


# ===========================================================================
# Gx  —  PCEF ↔ PCRF  (TS 29.212)
# ===========================================================================

# ---------------------------------------------------------------------------
# Credit-Control  (CCR / CCA)  — code 272
# ---------------------------------------------------------------------------

def ccr_gx(
    origin_host: str = "pcef.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "pcrf.example.com",
    destination_realm: str = "example.com",
    cc_request_type: str = "INITIAL_REQUEST",
    cc_request_number: int = 0,
    user_name: Optional[str] = None,
    ip_can_type: str = "3GPP-EPS",
    rat_type: str = "EUTRAN",
    bearer_operation: str = "ESTABLISHMENT",
    network_request_support: int = 0,
    supported_features_avps: Optional[List[AVP]] = None,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Credit-Control-Request (CCR)  TS 29.212 §4.6.3  [Gx interface].

    Sent by the PCEF to the PCRF to request PCC rules for a bearer.

    Parameters
    ----------
    cc_request_type : str
        ``"INITIAL_REQUEST"``, ``"UPDATE_REQUEST"``, or
        ``"TERMINATION_REQUEST"``.
    cc_request_number : int
        Monotonically increasing counter per session.
    ip_can_type : str
        IP-CAN-Type enum name (e.g. ``"3GPP-EPS"``).
    rat_type : str
        RAT-Type enum name (e.g. ``"EUTRAN"``, ``"NR"``).
    bearer_operation : str
        Bearer-Operation enum name (``"ESTABLISHMENT"``, ``"MODIFICATION"``,
        ``"TERMINATION"``).
    network_request_support : int
        Network-Request-Support (0 = not supported, 1 = supported).
    """
    avps = _base_request("Credit-Control", APP_GX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    if user_name:
        avps.append(AVP("User-Name", user_name))
    avps += [
        AVP("CC-Request-Type", cc_request_type),
        AVP("CC-Request-Number", cc_request_number),
        AVP("IP-CAN-Type", ip_can_type),
        AVP("RAT-Type", rat_type),
        AVP("Bearer-Operation", bearer_operation),
        AVP("Network-Request-Support", "NETWORK_REQUEST NOT SUPPORTED"
            if network_request_support == 0 else "NETWORK_REQUEST SUPPORTED"),
    ]
    if supported_features_avps:
        for sf in supported_features_avps:
            avps.append(sf)
    else:
        avps.append(AVP("Supported-Features", [
            AVP("Vendor-Id", VENDOR_3GPP),
            AVP("Feature-List-ID", 1),
            AVP("Feature-List", 0x0000007F),
        ]))
    if extra_avps:
        avps += extra_avps
    return Message("Credit-Control", APP_GX, is_request=True,
                   is_proxiable=True, avps=avps)


def cca_gx(
    origin_host: str = "pcrf.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    cc_request_type: str = "INITIAL_REQUEST",
    cc_request_number: int = 0,
    charging_rule_install_avps: Optional[List[AVP]] = None,
    supported_features_avps: Optional[List[AVP]] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Credit-Control-Answer (CCA)  TS 29.212 §4.6.4  [Gx interface].

    Parameters
    ----------
    charging_rule_install_avps : list[AVP], optional
        Child AVPs of Charging-Rule-Install.  A default permit-all rule
        is included when omitted.
    """
    avps = _base_answer("Credit-Control", APP_GX,
                        origin_host, origin_realm, session_id, result_code)
    avps += [
        AVP("CC-Request-Type", cc_request_type),
        AVP("CC-Request-Number", cc_request_number),
    ]
    if supported_features_avps:
        for sf in supported_features_avps:
            avps.append(sf)
    else:
        avps.append(AVP("Supported-Features", [
            AVP("Vendor-Id", VENDOR_3GPP),
            AVP("Feature-List-ID", 1),
            AVP("Feature-List", 0x0000007F),
        ]))
    rule_install = charging_rule_install_avps or [
        AVP("Charging-Rule-Definition", [
            AVP("Charging-Rule-Name", b"default-rule"),
            AVP("Precedence", 100),
            AVP("Flow-Information", [
                AVP("Flow-Description", "permit out ip from any to assigned"),
                AVP("Flow-Direction", "BIDIRECTIONAL"),
            ]),
            AVP("QoS-Information", [
                AVP("QoS-Class-Identifier", "QCI_9"),
                AVP("Max-Requested-Bandwidth-UL", 1000000),
                AVP("Max-Requested-Bandwidth-DL", 1000000),
                AVP("Guaranteed-Bitrate-UL", 0),
                AVP("Guaranteed-Bitrate-DL", 0),
            ]),
        ]),
    ]
    avps.append(AVP("Charging-Rule-Install", rule_install))
    if extra_avps:
        avps += extra_avps
    return Message("Credit-Control", APP_GX, is_request=False,
                   is_proxiable=True, avps=avps)


# ---------------------------------------------------------------------------
# Re-Auth  (RAR / RAA)  — code 258  [Gx interface, PCRF→PCEF]
# ---------------------------------------------------------------------------

def rar_gx(
    origin_host: str = "pcrf.example.com",
    origin_realm: str = "example.com",
    destination_host: str = "pcef.example.com",
    destination_realm: str = "example.com",
    re_auth_request_type: int = 0,
    event_trigger: Optional[str] = None,
    charging_rule_install_avps: Optional[List[AVP]] = None,
    charging_rule_remove_avps: Optional[List[AVP]] = None,
    session_id: Optional[str] = None,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """
    Re-Auth-Request (RAR)  TS 29.212 §4.6.5  [Gx interface].

    Sent by the PCRF to the PCEF to push updated PCC rules mid-session.

    Parameters
    ----------
    event_trigger : str, optional
        Event-Trigger enum name that triggered this RAR.
    charging_rule_install_avps : list[AVP], optional
        Rules to install (child AVPs of Charging-Rule-Install).
    charging_rule_remove_avps : list[AVP], optional
        Rules to remove (child AVPs of Charging-Rule-Remove).
    """
    avps = _base_request("Re-Auth", APP_GX,
                         origin_host, origin_realm,
                         destination_host, destination_realm,
                         session_id)
    avps.append(AVP("Re-Auth-Request-Type", re_auth_request_type))
    if event_trigger is not None:
        avps.append(AVP("Event-Trigger", event_trigger))
    if charging_rule_install_avps:
        avps.append(AVP("Charging-Rule-Install", charging_rule_install_avps))
    if charging_rule_remove_avps:
        avps.append(AVP("Charging-Rule-Remove", charging_rule_remove_avps))
    if extra_avps:
        avps += extra_avps
    return Message("Re-Auth", APP_GX, is_request=True,
                   is_proxiable=True, avps=avps)


def raa_gx(
    origin_host: str = "pcef.example.com",
    origin_realm: str = "example.com",
    session_id: str = "session-id",
    result_code: int = SUCCESS,
    extra_avps: Optional[List[AVP]] = None,
) -> Message:
    """Re-Auth-Answer (RAA)  TS 29.212 §4.6.6  [Gx interface]."""
    avps = _base_answer("Re-Auth", APP_GX,
                        origin_host, origin_realm, session_id, result_code)
    if extra_avps:
        avps += extra_avps
    return Message("Re-Auth", APP_GX, is_request=False,
                   is_proxiable=True, avps=avps)

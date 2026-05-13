# diameter-codec

A Python library for encoding and decoding Diameter protocol messages (RFC 6733),
driven by Wireshark-format XML dictionary files.

The dictionary format is the same one used by Wireshark's Diameter dissector —
a root `dictionary.xml` that pulls in vendor-specific files (`TGPP.xml`,
`nasreq.xml`, etc.) via XML entity references.  Loading a single file gives you
the full set of 2 700+ AVPs across 33+ vendors.

---

## Requirements

- Python 3.6+
- Standard library only for the core codec (`diameter/`)
- `flask` for the TCP peer programs (`server.py`, `client.py`)

---

## Installation

Clone the repository and import directly — no build step required.

```
git clone https://github.com/example/diameter-codec
cd diameter-codec
pip install flask          # only needed for server.py / client.py
```

---

## Repository layout

```
diameter/               Core codec library (no third-party dependencies)
  __init__.py             Public API: Dictionary, AVP, Message
  dictionary.py           XML parser — AVP / command / vendor registry
  avp.py                  AVP class — per-type encoding and decoding
  message.py              Message class — header encoding and decoding
  tgpp.py                 3GPP message factories (102 functions)
  ietf.py                 IETF message factories (NASREQ, CC, EAP, Accounting)
  xml/                    Wireshark dictionary files (33+ vendor files)

peer.py                 Shared TCP-framing and tgpp-registry utilities
server.py               Diameter TCP server + HTTP management API
client.py               Diameter TCP client + HTTP management API
test_harness.py         End-to-end test: starts both peers, sends all message types
example.py              Standalone encode/decode walkthrough
```

---

## Quick start

```python
from diameter import Dictionary, Message, AVP

# Load the dictionary once (resolves all vendor XML files automatically)
d = Dictionary()

# Build a Capabilities-Exchange-Request (CER)
msg = Message(
    command="Capabilities-Exchange",
    app_id=0,
    is_request=True,
    avps=[
        AVP("Origin-Host", "node.example.com"),
        AVP("Origin-Realm", "example.com"),
        AVP("Host-IP-Address", "192.0.2.1"),
        AVP("Vendor-Id", 0),
        AVP("Product-Name", "my-agent"),
        AVP("Auth-Application-Id", 0),
    ],
)

# Encode to bytes
raw = msg.encode(d)

# Decode from bytes
msg2 = Message.decode(raw, d)

print(msg2.command)                          # "Capabilities-Exchange"
print(msg2.get_avp("Origin-Host").value)     # "node.example.com"
print(msg2.get_avp("Host-IP-Address").value) # "192.0.2.1"
```

---

## Message factories

### 3GPP (`diameter/tgpp.py`)

102 factory functions covering every 3GPP Diameter interface.  Each function
returns a ready-to-encode `Message` with sensible AVP defaults; every parameter
can be overridden, and `extra_avps` accepts additional AVPs.

```python
from diameter import Dictionary, tgpp

d = Dictionary()

# Update-Location-Request with defaults
msg = tgpp.ulr()

# Override specific fields
msg = tgpp.ulr(
    origin_host="mme.mnc051.mcc262.3gppnetwork.org",
    user_name="262051234567890",
    visited_plmn_id=b"\x62\xf2\x10",
    rat_type="EUTRAN",
)

print(msg.encode(d).hex())
```

Interfaces covered:

| Interface | App-ID | Functions |
|-----------|--------|-----------|
| Base protocol (RFC 6733) | 0 | `cer/cea`, `dwr/dwa`, `dpr/dpa` |
| S6a / S6d — MME ↔ HSS (TS 29.272) | 16777251 | `ulr/ula`, `clr/cla`, `air/aia`, `idr/ida`, `dsr/dsa`, `pur_s6a/pua_s6a`, `rsr_s6a/rsa_s6a`, `nor/noa` |
| S13 — MME ↔ EIR (TS 29.272) | 16777252 | `ecr/eca` |
| Cx — CSCF ↔ HSS (TS 29.229) | 16777216 | `uar/uaa`, `sar/saa`, `lir/lia`, `mar/maa`, `rtr/rta`, `ppr/ppa` |
| Sh — AS ↔ HSS (TS 29.329) | 16777217 | `udr/uda`, `pur_sh/pua_sh`, `snr/sna`, `pnr/pna` |
| Rx — AF ↔ PCRF (TS 29.214) | 16777236 | `aar_rx/aaa_rx`, `str_rx/sta_rx`, `rar_rx/raa_rx`, `asr_rx/asa_rx` |
| Gx — PCEF ↔ PCRF (TS 29.212) | 16777238 | `ccr_gx/cca_gx`, `rar_gx/raa_gx` |
| SLg — GMLC ↔ MME (TS 29.172) | 16777255 | `plr/pla`, `lrr/lra`, `rir/ria` |
| Sy — PCRF ↔ OCS (TS 29.219) | 16777302 | `slr/sla`, `ssn/ssa` |
| Sd — PCRF ↔ TDF (TS 29.212) | 16777303 | `tsr/tsa` |
| S6m — SCEF ↔ HSS (TS 29.336) | 16777310 | `sir/sia`, `nir/nia` |
| S6c — SMS routing (TS 29.338) | 16777312 | `srr/sra`, `mofr/mofa`, `mtfr/mtfa`, `alr/ala`, `rdsr/rdsa` |
| T6a/T6b — SCEF ↔ MME (TS 29.128) | 16777346 | `cmr/cma`, `modr/moda`, `mtdr/mtda` |
| MB2c / GCS — BM-SC ↔ GCS AS (TS 29.468) | 16777335 | `gar/gaa`, `gnr/gna` |
| PC4a / ProSe — ProSe ↔ HSS (TS 29.344) | 16777336 | `pir/pia`, `upr/upa`, `prose_pnr/prose_pna`, `rsr_prose/rsa_prose`, `psr/psa` |

### IETF (`diameter/ietf.py`)

Factory functions for the standard IETF Diameter applications, complementing the
3GPP set above.

```python
from diameter import Dictionary
from diameter import ietf

d = Dictionary()

# NASREQ (RFC 7155, App-ID 1) — AA-Request / AA-Answer
aar = ietf.aar(user_name="alice@example.com", nas_ip_address="10.0.0.1")
aaa = ietf.aaa(result_code=2001)

# Credit-Control (RFC 4006, App-ID 4) — Gy / Ro
ccr = ietf.ccr(
    cc_request_type="INITIAL_REQUEST",
    subscription_id_data="001010123456789",
    requested_units=3600,
)
cca = ietf.cca(granted_units=3600, validity_time=3600)

# EAP (RFC 4072, App-ID 5)
der = ietf.der(eap_payload=b"\x02\x01\x00\x04")
dea = ietf.dea(eap_payload=b"\x03\x01\x00\x04", eap_master_session_key=b"\x00" * 64)

# Accounting (RFC 6733 §9, App-ID 3)
acr = ietf.acr(accounting_record_type="Start Record")
aca = ietf.aca(accounting_record_type="Start Record")

# Generic Re-Auth / Session-Termination / Abort-Session (any app_id)
r = ietf.rar(app_id=ietf.APP_NASREQ, re_auth_request_type="AUTHORIZE_ONLY")
s = ietf.str_(app_id=ietf.APP_CC, termination_cause="DIAMETER_LOGOUT")
a = ietf.asr(app_id=ietf.APP_EAP)
```

---

## TCP peer programs

`server.py` and `client.py` implement a Diameter TCP transport layer on top of the
codec.  Each exposes an HTTP management API so that an HTTP client can direct what
messages to send and retrieve messages that have been received.

### Running

```bash
# Terminal 1 — server
python server.py                           # TCP :3868  HTTP :8001

# Terminal 2 — client (auto-reconnects on disconnect)
python client.py                           # → TCP :3868  HTTP :8002
```

Both programs accept `--tcp-host`, `--tcp-port`, `--http-host`, `--http-port`.

### HTTP API

Both the server and client expose identical endpoints (on different ports).

#### Received messages

```
GET  /messages          Return all received messages as JSON.
                        Add ?download=1 to get a file attachment.

DELETE /messages        Clear the received-message list.
                        Returns {"cleared": <count>}.
```

Each message record in the response looks like:

```json
{
  "timestamp": "2024-01-01T12:00:00+00:00",
  "source":    "192.0.2.10:38412",
  "command":   "3GPP-Update-Location",
  "is_request": true,
  "is_proxiable": true,
  "is_error":  false,
  "app_id":    16777251,
  "hop_by_hop_id": 3735928559,
  "end_to_end_id": 3735928559,
  "avps": [
    {"name": "Session-Id",  "value": "mme.example.com;1700000000;42"},
    {"name": "Vendor-Specific-Application-Id", "value": [
      {"name": "Vendor-Id",           "value": 10415},
      {"name": "Auth-Application-Id", "value": 16777251}
    ]},
    {"name": "Visited-PLMN-Id", "value": "00f110"}
  ],
  "raw_hex": "010001..."
}
```

`bytes`-typed AVP values are hex-encoded strings.  Grouped AVPs are nested lists.

#### Sending messages

```
GET  /functions                Return all available factory functions with
                               their parameter schemas.

GET  /functions/<name>         Schema for a single function.

POST /send/<func>              Build and send a message.  Body is a JSON object
                               with the function's kwargs; omitted params use
                               their defaults.  bytes params take hex strings.
```

**Example — send a ULR from the client:**

```bash
curl -X POST http://127.0.0.1:8002/send/ulr \
  -H 'Content-Type: application/json' \
  -d '{
    "origin_host":       "mme.mnc051.mcc262.3gppnetwork.org",
    "user_name":         "262051234567890",
    "visited_plmn_id":   "62f210",
    "rat_type":          "EUTRAN"
  }'
```

Response:

```json
{"sent": true, "bytes": 272, "command": "3GPP-Update-Location", "is_request": true}
```

**Example — download received messages:**

```bash
curl http://127.0.0.1:8001/messages?download=1 -o messages.json
```

**Example — clear received messages:**

```bash
curl -X DELETE http://127.0.0.1:8001/messages
```

#### Status

```
GET /status             Connection state and message count.
```

Server response:

```json
{"connected_clients": 1, "received_messages": 42}
```

Client response:

```json
{"connected": true, "server": "127.0.0.1:3868", "received_messages": 17}
```

### `peer.py` — shared utilities

`peer.py` is used internally by `server.py` and `client.py`.  Its public symbols
are also useful directly:

```python
import peer

# TCP framing — read exactly one Diameter message from a blocking socket
raw = peer.read_message(sock)               # bytes | None

# Decode raw bytes with the shared Dictionary
msg = peer.decode_message(raw)

# Serialise to JSON-compatible dict (bytes → hex, grouped AVPs → nested dicts)
d   = peer.msg_to_dict(msg, source="10.0.0.1:38412", raw=raw)

# Registry of all 102 tgpp factory functions
peer.TGPP_FUNCTIONS                         # dict[str, Callable]

# Introspect a function's parameters (AVP-list params are hidden)
schema = peer.function_schema(peer.TGPP_FUNCTIONS["ulr"])

# Build a Message from a JSON body dict (hex strings → bytes, etc.)
msg = peer.build_message("ulr", {"user_name": "001010123456789"})
```

---

## Test harness

`test_harness.py` starts both peer programs as subprocesses, waits for the
TCP connection to be established, sends all 102 message types via the HTTP API,
and verifies that the server received every message.

```bash
python test_harness.py
```

```
================================================================
  Diameter Client/Server Test Harness
================================================================

[1/5] Starting subprocesses
    server  PID 11342  (TCP 127.0.0.1:13868  HTTP :18001)
    client  PID 11343  (→ TCP :13868  HTTP :18002)

[2/5] Waiting for readiness  (timeout 20s)
    server HTTP API                     ready
    client HTTP API                     ready
    client → server TCP                 connected

[3/5] Discovering available functions
    102 tgpp functions registered

[4/5] Sending all 102 message types via client HTTP API
    cer    OK  Capabilities-Exchange          140 bytes
    ulr    OK  3GPP-Update-Location           272 bytes
    ...

[5/5] Verifying receipt on server  (waiting 1.0s)

================================================================
  SUMMARY
================================================================
    Functions registered :  102
    Sent OK (HTTP 200)         102 / 102
    Send errors                  0 / 102
    Received by server         102 / 102
    Elapsed              : 0.13s
================================================================
```

Non-standard ports are used by default (`TCP 13868`, HTTP `18001`/`18002`) so the
harness does not interfere with a live Diameter stack.  Override with:

```bash
python test_harness.py --tcp-port 23868 --server-http 28001 --client-http 28002
```

---

## Technical description

### Dictionary

`Dictionary` resolves the full chain of Wireshark XML entity references before
parsing, so a single `Dictionary()` call loads every vendor file:

```python
d = Dictionary()                    # auto-loads diameter/xml/dictionary.xml
d = Dictionary("/path/to/dict.xml") # custom path
```

After loading you can query any definition directly:

```python
avp_def = d.get_avp("Origin-Host")
# AVPDef(name='Origin-Host', code=264, vendor_code=0,
#        encoding='utf8', mandatory='must', ...)

cmd_def = d.get_command("Capabilities-Exchange")
# CommandDef(name='Capabilities-Exchange', code=257, ...)

vendor = d.get_vendor("TGPP")
# VendorDef(vendor_id='TGPP', code=10415, name='3GPP')
```

### AVP types

All RFC 6733 base types are supported, plus Address and the UTF-8 string family:

| XML type | Python value on encode | Python value on decode |
|----------|------------------------|------------------------|
| `OctetString` and derivatives | `bytes` | `bytes` |
| `UTF8String`, `DiameterIdentity`, `DiameterURI`, filter rules | `str` or `bytes` | `str` |
| `Integer32`, `Integer64` | `int` | `int` |
| `Unsigned32`, `Unsigned64`, `Time`, `VendorId` | `int` | `int` |
| `Float32`, `Float64` | `float` | `float` |
| `Enumerated` | `int` or enum name `str` | enum name `str` (or `int` if unknown) |
| `Address`, `IPAddress` | dotted-quad / colon-hex `str` or `bytes` | `str` |
| `Grouped` | `list[AVP]` | `list[AVP]` |

### AVP encoding

```python
# String types
AVP("Origin-Host", "node.example.com")

# Integer types
AVP("Auth-Application-Id", 16777238)

# Enumerated — by name or by integer code
AVP("Accounting-Record-Type", "Start Record")
AVP("Accounting-Record-Type", 2)

# Address — IPv4 or IPv6
AVP("Host-IP-Address", "192.0.2.1")
AVP("Host-IP-Address", "2001:db8::1")

# Raw bytes
AVP("State", b"\x01\x02\x03\x04")

# Grouped — list of child AVPs
AVP("Tunneling", [
    AVP("Tunnel-Type", 13),
    AVP("Tunnel-Medium-Type", 1),
    AVP("Tunnel-Client-Endpoint", "10.0.0.1"),
    AVP("Tunnel-Server-Endpoint", "10.0.0.2"),
])

# Vendor-specific AVP (vendor code auto-resolved from dictionary)
AVP("3GPP-IMSI", "310260123456789")
```

### Message encoding

`Message` accepts a command name or numeric code and a list of `AVP` objects.
Hop-by-Hop and End-to-End identifiers are generated automatically if omitted.

```python
msg = Message(
    command="Re-Auth",        # or command=258
    app_id=0,
    is_request=False,         # answer
    is_proxiable=True,
    hop_by_hop_id=0x1234,     # optional — auto-generated if omitted
    end_to_end_id=0x5678,
    avps=[...],
)

raw = msg.encode(d)           # → bytes
```

### Message decoding

```python
msg = Message.decode(raw, d)

msg.command        # command name string, or int if unknown
msg.app_id         # int
msg.is_request     # bool
msg.is_proxiable   # bool
msg.is_error       # bool
msg.is_retransmit  # bool
msg.hop_by_hop_id  # int
msg.end_to_end_id  # int
msg.avps           # list[AVP]

msg.get_avp("Origin-Host")         # first matching AVP, or None
msg.get_avps("Proxy-State")        # all matching AVPs
```

### Wire format

The library encodes to and decodes from the standard Diameter wire format
defined in RFC 6733:

**Message header (20 bytes)**

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |                 Message Length                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R P E T r r r r|                  Command Code                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Application-ID                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Hop-by-Hop Identifier                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      End-to-End Identifier                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**AVP header (8 bytes, or 12 bytes with Vendor-ID)**

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           AVP Code                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V M P r r r r r|                  AVP Length                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Vendor-ID (opt)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Data ...
+-+-+-+-+-+-+-+-+
```

AVP data is zero-padded to the next 4-byte boundary; the padding bytes are
not counted in the AVP Length field.

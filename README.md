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
- Standard library only (no third-party dependencies)

---

## Installation

Clone the repository and import directly — no build step required.

```
git clone https://github.com/example/diameter-codec
cd diameter-codec
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

## Technical description

### Library layout

```
diameter/
  __init__.py      # public API  (Dictionary, AVP, Message)
  dictionary.py    # XML parser and AVP/command/vendor registry
  avp.py           # AVP class — per-type encoding and decoding
  message.py       # Message class — header encoding and decoding
  xml/             # Wireshark dictionary files
    dictionary.xml
    TGPP.xml
    nasreq.xml
    ... (30+ files)
```

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

| XML type                                               | Python value on encode     | Python value on decode |
|--------------------------------------------------------|----------------------------|------------------------|
| `OctetString` and derivatives                          | `bytes`                    | `bytes`                |
| `UTF8String`, `DiameterIdentity`, `DiameterURI`, filter rules | `str` or `bytes`  | `str`                  |
| `Integer32`, `Integer64`                               | `int`                      | `int`                  |
| `Unsigned32`, `Unsigned64`, `Time`, `VendorId`         | `int`                      | `int`                  |
| `Float32`, `Float64`                                   | `float`                    | `float`                |
| `Enumerated`                                           | `int` or enum name `str`   | enum name `str` (or `int` if unknown) |
| `Address`, `IPAddress`                                 | dotted-quad / colon-hex `str` or `bytes` | `str`    |
| `Grouped`                                              | `list[AVP]`                | `list[AVP]`            |

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

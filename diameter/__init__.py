"""
diameter-codec
==============

A Python library for encoding and decoding Diameter protocol messages
(RFC 6733), driven by Wireshark-format XML dictionary files.

Quick start
-----------
>>> from diameter import Dictionary, Message, AVP
>>>
>>> d = Dictionary()          # auto-loads diameter/xml/dictionary.xml
>>>
>>> msg = Message(
...     command="Capabilities-Exchange",
...     app_id=0,
...     is_request=True,
...     avps=[
...         AVP("Origin-Host", "my.node.example.com"),
...         AVP("Origin-Realm", "example.com"),
...         AVP("Host-IP-Address", "192.0.2.1"),
...         AVP("Vendor-Id", 0),
...         AVP("Product-Name", "diameter-codec"),
...         AVP("Auth-Application-Id", 0),
...     ],
... )
>>>
>>> raw = msg.encode(d)       # → bytes
>>> msg2 = Message.decode(raw, d)
>>> msg2.get_avp("Origin-Host").value
'my.node.example.com'
"""

from .dictionary import Dictionary, AVPDef, CommandDef, VendorDef
from .avp import AVP
from .message import Message

__all__ = [
    "Dictionary",
    "AVPDef",
    "CommandDef",
    "VendorDef",
    "AVP",
    "Message",
]

__version__ = "0.1.0"

import binascii
from diameter import Dictionary, Message, AVP, tgpp

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

sample = binascii.a2b_hex("010000d4c000013e0100002300002dc300043547000001150000000c0000000000000108000000346f7269676974686f73742e6570632e6d6e633035312e6d63633236322e336770706e6574776f726b2e6f726700000128000000296570632e6d6e633035312e6d63633236322e336770706e6574776f726b2e6f72670000000000011b000000296570632e6d6e633030392e6d63633230382e336770706e6574776f726b2e6f72670000000000000100000017353432393931313131313131313131000000057f8000000f000028af62125000")
msg3 = Message.decode(sample, d)
print(msg3.command)                       
print(msg3.get_avp("Origin-Host").value)  
print(msg3.get_avp("Origin-Realm").value)  
print(msg3)

ula = tgpp.ula()
print(ula)
print(binascii.b2a_hex(ula.encode(d)))

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
rir = tgpp.rir()
print(rir)
print(binascii.b2a_hex(rir.encode(d)))


def generate_all_messages(output_path: str = "messages.hex") -> None:
    """
    Generate one instance of every 3GPP Diameter message type defined in
    ``diameter.tgpp`` and write each encoded message as a hex string to
    *output_path*.

    The output file format is plain text::

        # <function_name> (<short description>)
        <hex string>

    Sections are separated by blank lines and grouped by interface.
    """

    # Each entry: (section_header, [(func, label), ...])
    sections = [
        ("Base protocol — RFC 6733  (peer management, app_id=0)", [
            (tgpp.cer,        "cer  — Capabilities-Exchange-Request"),
            (tgpp.cea,        "cea  — Capabilities-Exchange-Answer"),
            (tgpp.dwr,        "dwr  — Device-Watchdog-Request"),
            (tgpp.dwa,        "dwa  — Device-Watchdog-Answer"),
            (tgpp.dpr,        "dpr  — Disconnect-Peer-Request"),
            (tgpp.dpa,        "dpa  — Disconnect-Peer-Answer"),
        ]),
        ("S6a / S6d — MME/SGSN ↔ HSS  (TS 29.272, App-ID 16777251)", [
            (tgpp.ulr,        "ulr  — Update-Location-Request"),
            (tgpp.ula,        "ula  — Update-Location-Answer"),
            (tgpp.clr,        "clr  — Cancel-Location-Request"),
            (tgpp.cla,        "cla  — Cancel-Location-Answer"),
            (tgpp.air,        "air  — Authentication-Information-Request"),
            (tgpp.aia,        "aia  — Authentication-Information-Answer"),
            (tgpp.idr,        "idr  — Insert-Subscriber-Data-Request"),
            (tgpp.ida,        "ida  — Insert-Subscriber-Data-Answer"),
            (tgpp.dsr,        "dsr  — Delete-Subscriber-Data-Request"),
            (tgpp.dsa,        "dsa  — Delete-Subscriber-Data-Answer"),
            (tgpp.pur_s6a,    "pur_s6a — Purge-UE-Request"),
            (tgpp.pua_s6a,    "pua_s6a — Purge-UE-Answer"),
            (tgpp.rsr_s6a,    "rsr_s6a — Reset-Request"),
            (tgpp.rsa_s6a,    "rsa_s6a — Reset-Answer"),
            (tgpp.nor,        "nor  — Notify-Request"),
            (tgpp.noa,        "noa  — Notify-Answer"),
        ]),
        ("S13 — MME ↔ EIR  (TS 29.272, App-ID 16777252)", [
            (tgpp.ecr,        "ecr  — ME-Identity-Check-Request"),
            (tgpp.eca,        "eca  — ME-Identity-Check-Answer"),
        ]),
        ("Cx — S-CSCF/I-CSCF ↔ HSS  (TS 29.229, App-ID 16777216)", [
            (tgpp.uar,        "uar  — User-Authorization-Request"),
            (tgpp.uaa,        "uaa  — User-Authorization-Answer"),
            (tgpp.sar,        "sar  — Server-Assignment-Request"),
            (tgpp.saa,        "saa  — Server-Assignment-Answer"),
            (tgpp.lir,        "lir  — Location-Info-Request"),
            (tgpp.lia,        "lia  — Location-Info-Answer"),
            (tgpp.mar,        "mar  — Multimedia-Auth-Request"),
            (tgpp.maa,        "maa  — Multimedia-Auth-Answer"),
            (tgpp.rtr,        "rtr  — Registration-Termination-Request"),
            (tgpp.rta,        "rta  — Registration-Termination-Answer"),
            (tgpp.ppr,        "ppr  — Push-Profile-Request"),
            (tgpp.ppa,        "ppa  — Push-Profile-Answer"),
        ]),
        ("Sh — AS/MRFC ↔ HSS  (TS 29.329, App-ID 16777217)", [
            (tgpp.udr,        "udr  — User-Data-Request"),
            (tgpp.uda,        "uda  — User-Data-Answer"),
            (tgpp.pur_sh,     "pur_sh — Profile-Update-Request"),
            (tgpp.pua_sh,     "pua_sh — Profile-Update-Answer"),
            (tgpp.snr,        "snr  — Subscribe-Notifications-Request"),
            (tgpp.sna,        "sna  — Subscribe-Notifications-Answer"),
            (tgpp.pnr,        "pnr  — Push-Notification-Request"),
            (tgpp.pna,        "pna  — Push-Notification-Answer"),
        ]),
        ("Rx — AF ↔ PCRF  (TS 29.214, App-ID 16777236)", [
            (tgpp.aar_rx,     "aar_rx  — AA-Request"),
            (tgpp.aaa_rx,     "aaa_rx  — AA-Answer"),
            (tgpp.str_rx,     "str_rx  — Session-Termination-Request"),
            (tgpp.sta_rx,     "sta_rx  — Session-Termination-Answer"),
            (tgpp.rar_rx,     "rar_rx  — Re-Auth-Request"),
            (tgpp.raa_rx,     "raa_rx  — Re-Auth-Answer"),
            (tgpp.asr_rx,     "asr_rx  — Abort-Session-Request"),
            (tgpp.asa_rx,     "asa_rx  — Abort-Session-Answer"),
        ]),
        ("Gx — PCEF ↔ PCRF  (TS 29.212, App-ID 16777238)", [
            (tgpp.ccr_gx,     "ccr_gx  — Credit-Control-Request"),
            (tgpp.cca_gx,     "cca_gx  — Credit-Control-Answer"),
            (tgpp.rar_gx,     "rar_gx  — Re-Auth-Request"),
            (tgpp.raa_gx,     "raa_gx  — Re-Auth-Answer"),
        ]),
        ("SLg — GMLC ↔ MME/SGSN  (TS 29.172, App-ID 16777255)", [
            (tgpp.plr,        "plr  — Provide-Location-Request"),
            (tgpp.pla,        "pla  — Provide-Location-Answer"),
            (tgpp.lrr,        "lrr  — Location-Report-Request"),
            (tgpp.lra,        "lra  — Location-Report-Answer"),
            (tgpp.rir,        "rir  — LCS-Routing-Info-Request"),
            (tgpp.ria,        "ria  — LCS-Routing-Info-Answer"),
        ]),
        ("Sy — PCRF ↔ OCS  (TS 29.219, App-ID 16777302)", [
            (tgpp.slr,        "slr  — Spending-Limit-Request"),
            (tgpp.sla,        "sla  — Spending-Limit-Answer"),
            (tgpp.ssn,        "ssn  — Spending-Status-Notification-Request"),
            (tgpp.ssa,        "ssa  — Spending-Status-Notification-Answer"),
        ]),
        ("Sd — PCRF ↔ TDF  (TS 29.212, App-ID 16777303)", [
            (tgpp.tsr,        "tsr  — TDF-Session-Request"),
            (tgpp.tsa,        "tsa  — TDF-Session-Answer"),
        ]),
        ("S6m — SCEF ↔ HSS  (TS 29.336, App-ID 16777310)", [
            (tgpp.sir,        "sir  — Subscriber-Information-Request"),
            (tgpp.sia,        "sia  — Subscriber-Information-Answer"),
            (tgpp.nir,        "nir  — NIDD-Information-Request"),
            (tgpp.nia,        "nia  — NIDD-Information-Answer"),
        ]),
        ("S6c — SMS routing  (TS 29.338, App-ID 16777312)", [
            (tgpp.srr,        "srr  — Send-Routing-Info-for-SM-Request"),
            (tgpp.sra,        "sra  — Send-Routing-Info-for-SM-Answer"),
            (tgpp.mofr,       "mofr — MO-Forward-Short-Message-Request"),
            (tgpp.mofa,       "mofa — MO-Forward-Short-Message-Answer"),
            (tgpp.mtfr,       "mtfr — MT-Forward-Short-Message-Request"),
            (tgpp.mtfa,       "mtfa — MT-Forward-Short-Message-Answer"),
            (tgpp.alr,        "alr  — Alert-Service-Centre-Request"),
            (tgpp.ala,        "ala  — Alert-Service-Centre-Answer"),
            (tgpp.rdsr,       "rdsr — Report-SM-Delivery-Status-Request"),
            (tgpp.rdsa,       "rdsa — Report-SM-Delivery-Status-Answer"),
        ]),
        ("T6a / T6b — SCEF ↔ MME/SGSN  (TS 29.128, App-ID 16777346)", [
            (tgpp.cmr,        "cmr  — Connection-Management-Request"),
            (tgpp.cma,        "cma  — Connection-Management-Answer"),
            (tgpp.modr,       "modr — MO-Data-Request"),
            (tgpp.moda,       "moda — MO-Data-Answer"),
            (tgpp.mtdr,       "mtdr — MT-Data-Request"),
            (tgpp.mtda,       "mtda — MT-Data-Answer"),
        ]),
        ("MB2c / GCS — BM-SC ↔ GCS AS  (TS 29.468, App-ID 16777335)", [
            (tgpp.gar,        "gar  — GCS-Action-Request"),
            (tgpp.gaa,        "gaa  — GCS-Action-Answer"),
            (tgpp.gnr,        "gnr  — GCS-Notification-Request"),
            (tgpp.gna,        "gna  — GCS-Notification-Answer"),
        ]),
        ("PC4a / ProSe — ProSe Function ↔ HSS  (TS 29.344, App-ID 16777336)", [
            (tgpp.pir,        "pir  — ProSe-Subscriber-Information-Request"),
            (tgpp.pia,        "pia  — ProSe-Subscriber-Information-Answer"),
            (tgpp.upr,        "upr  — Update-ProSe-Subscriber-Data-Request"),
            (tgpp.upa,        "upa  — Update-ProSe-Subscriber-Data-Answer"),
            (tgpp.prose_pnr,  "prose_pnr — ProSe-Notify-Request"),
            (tgpp.prose_pna,  "prose_pna — ProSe-Notify-Answer"),
            (tgpp.rsr_prose,  "rsr_prose — Reset-Request [PC4a]"),
            (tgpp.rsa_prose,  "rsa_prose — Reset-Answer [PC4a]"),
            (tgpp.psr,        "psr  — ProSe-Initial-Location-Information-Request"),
            (tgpp.psa,        "psa  — ProSe-Initial-Location-Information-Answer"),
        ]),
    ]

    total = 0
    with open(output_path, "w") as fh:
        for section_title, entries in sections:
            fh.write(f"# {'=' * 70}\n")
            fh.write(f"# {section_title}\n")
            fh.write(f"# {'=' * 70}\n\n")

            for func, label in entries:
                msg = func()
                hex_str = binascii.b2a_hex(msg.encode(d)).decode()
                fh.write(f"# {label}\n")
                fh.write(f"{hex_str}\n\n")
                total += 1

    print(f"Wrote {total} messages to {output_path!r}")


generate_all_messages()

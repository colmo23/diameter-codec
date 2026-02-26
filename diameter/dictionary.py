"""
Diameter dictionary loader.

Parses Wireshark-format XML dictionary files (dictionary.xml + companions)
and exposes AVP, command, and vendor lookups used by the encoder/decoder.

Structure parsed
----------------
<dictionary>
  <base>           – IETF base protocol (commands, type defs, AVPs)
  <application …>  – one per RFC / 3GPP spec
  <vendor …>       – one per vendor (may contain AVPs)
  <vendor …/>      – plain vendor-code registry entries (no children)
</dictionary>

External entity references (e.g. &TGPP; &nasreq;) are resolved by reading
the files declared in the DOCTYPE internal subset before handing the
resulting plain XML to ElementTree.
"""

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Type encoding map
# Maps a Diameter type name (as found in XML) → canonical encoding tag.
# The tag is then used by the AVP encoder/decoder.
# Types NOT in this map are resolved by walking the type-parent hierarchy
# until a known tag is reached (OctetString / 'bytes' is the final fallback).
# ---------------------------------------------------------------------------
_ENCODING_MAP: Dict[str, str] = {
    # Primitive wire types
    "OctetString":          "bytes",
    "Integer32":            "int32",
    "Integer64":            "int64",
    "Unsigned32":           "uint32",
    "Unsigned64":           "uint64",
    "Float32":              "float32",
    "Float64":              "float64",
    "Enumerated":           "enum",
    "Grouped":              "grouped",
    # Well-known OctetString derivatives that carry UTF-8 text
    "UTF8String":           "utf8",
    "DiameterIdentity":     "utf8",
    "DiameterURI":          "utf8",
    "IPFilterRule":         "utf8",
    "QoSFilterRule":        "utf8",
    "OctetStringOrUTF8":    "utf8",
    # Address types (2-byte family prefix + address bytes)
    "Address":              "address",
    "IPAddress":            "address",
    # Unsigned32 derivatives (Time has no type-parent in XML, hardcoded here)
    "Time":                 "uint32",
    "VendorId":             "uint32",
    "AppId":                "uint32",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VendorDef:
    vendor_id: str   # symbolic (e.g. "TGPP")
    code: int        # numeric (e.g. 10415)
    name: str        # display name (e.g. "3GPP")


@dataclass
class CommandDef:
    name: str
    code: int
    vendor_id: str


@dataclass
class AVPDef:
    name: str
    code: int
    vendor_code: int        # 0 for IETF AVPs
    vendor_id: str          # symbolic (e.g. "TGPP")
    encoding: str           # encoding tag (e.g. "utf8", "uint32", "grouped")
    raw_type: str           # type-name as in XML (e.g. "UTF8String")
    mandatory: str          # "must" | "may" | "mustnot" | "shouldnot"
    may_encrypt: bool
    protected: str
    vendor_bit: str
    enums: Dict[str, int]        # enum-name → code
    enum_by_code: Dict[int, str] # code → enum-name
    grouped_children: List[str]  # gavp names (informational)


# ---------------------------------------------------------------------------
# Dictionary
# ---------------------------------------------------------------------------

class Dictionary:
    """
    Loads a Wireshark-format Diameter XML dictionary and exposes lookup
    methods for AVPs, commands, and vendors.

    Parameters
    ----------
    path : str, optional
        Path to ``dictionary.xml``.  Defaults to the ``xml/`` subdirectory
        alongside this module.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        if path is None:
            path = os.path.join(os.path.dirname(__file__), "xml", "dictionary.xml")
        self._xml_dir = os.path.dirname(os.path.abspath(path))

        self.vendors: Dict[str, VendorDef] = {}
        self.vendor_by_code: Dict[int, VendorDef] = {}
        self.avp_by_name: Dict[str, AVPDef] = {}
        self.avp_by_code: Dict[Tuple[int, int], AVPDef] = {}
        self.commands_by_name: Dict[str, CommandDef] = {}
        self.commands_by_code: Dict[int, CommandDef] = {}
        # Seed with hardcoded parent mappings missing from the XML
        self._type_parent: Dict[str, Optional[str]] = {"Time": "Unsigned32"}

        self._load(path)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self, path: str) -> None:
        xml_text = self._preprocess(path)
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise RuntimeError(f"Failed to parse Diameter dictionary: {exc}") from exc

        # Pass 1 – vendor registry (needed before resolving AVP vendor codes)
        for vendor_el in root.iter("vendor"):
            self._register_vendor(vendor_el)

        # Pass 2 – type definitions
        base = root.find("base")
        if base is not None:
            self._parse_typedefns(base)
        for app_el in root.iter("application"):
            self._parse_typedefns(app_el)

        # Pass 3 – commands and AVPs
        if base is not None:
            self._parse_section(base, "None")
        for vendor_el in root.findall("vendor"):
            vid = vendor_el.get("vendor-id", "None")
            self._parse_section(vendor_el, vid)
        for app_el in root.findall("application"):
            self._parse_section(app_el, "None")

    # ------------------------------------------------------------------
    # XML pre-processing (entity resolution + DOCTYPE removal)
    # ------------------------------------------------------------------

    def _preprocess(self, path: str) -> str:
        """
        Read *path*, resolve all SYSTEM external entity references declared
        in the DOCTYPE internal subset, strip the DOCTYPE block, and return
        plain XML that ElementTree can parse.
        """
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()

        entities: Dict[str, str] = {}
        self._collect_entities(text, entities)

        # Remove the entire DOCTYPE declaration (with optional internal subset)
        text = re.sub(
            r"<!DOCTYPE\s[^[>]*(?:\[[^\]]*\])?[^>]*>",
            "",
            text,
            flags=re.DOTALL,
        )

        # Strip all XML / processing instructions
        text = re.sub(r"<\?[^?]*\?>", "", text)

        # Replace entity references with file contents
        for name, content in entities.items():
            text = text.replace(f"&{name};", content)

        return text.strip()

    def _collect_entities(self, text: str, entities: Dict[str, str]) -> None:
        """
        Populate *entities* from entity declarations found in *text*.

        Handles:
        * ``<!ENTITY % name SYSTEM "file">``  – parameter entity → recurse
        * ``<!ENTITY name SYSTEM "file">``    – external entity → load file
        * ``<!ENTITY name "value">``          – inline entity (e.g. empty)
        """
        # Strip XML comments so we don't match declarations inside <!-- ... -->
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

        # Parameter entities (load file and recurse for more declarations)
        for m in re.finditer(
            r'<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', text
        ):
            filepath = os.path.join(self._xml_dir, m.group(2))
            if os.path.isfile(filepath):
                with open(filepath, encoding="utf-8", errors="replace") as fh:
                    self._collect_entities(fh.read(), entities)

        # Regular SYSTEM entities
        for m in re.finditer(
            r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', text
        ):
            name, filename = m.group(1), m.group(2)
            if name in entities:
                continue
            filepath = os.path.join(self._xml_dir, filename)
            if os.path.isfile(filepath):
                with open(filepath, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                # Strip XML declaration / PIs from included fragments
                content = re.sub(r"<\?[^?]*\?>", "", content)
                entities[name] = content.strip()

        # Inline entity declarations (e.g. <!ENTITY Custom "">)
        for m in re.finditer(r'<!ENTITY\s+(\w+)\s+"([^"]*)"\s*>', text):
            name = m.group(1)
            if name not in entities:
                entities[name] = m.group(2)

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _register_vendor(self, el: ET.Element) -> None:
        vid = el.get("vendor-id", "")
        if not vid:
            return
        try:
            code = int(el.get("code", 0))
        except ValueError:
            code = 0
        name = el.get("name", vid)
        vd = VendorDef(vendor_id=vid, code=code, name=name)
        self.vendors[vid] = vd
        self.vendor_by_code[code] = vd

    def _parse_typedefns(self, el: ET.Element) -> None:
        for td in el.findall("typedefn"):
            type_name = td.get("type-name", "")
            parent = td.get("type-parent") or None
            if type_name and type_name not in self._type_parent:
                self._type_parent[type_name] = parent

    def _parse_section(self, el: ET.Element, default_vendor_id: str) -> None:
        for cmd_el in el.findall("command"):
            self._parse_command(cmd_el)
        for avp_el in el.findall("avp"):
            self._parse_avp(avp_el, default_vendor_id)

    def _parse_command(self, el: ET.Element) -> None:
        name = el.get("name", "")
        if not name:
            return
        try:
            code = int(el.get("code", 0))
        except ValueError:
            return
        vid = el.get("vendor-id", "None")
        cd = CommandDef(name=name, code=code, vendor_id=vid)
        self.commands_by_name.setdefault(name, cd)
        self.commands_by_code.setdefault(code, cd)

    def _parse_avp(self, el: ET.Element, default_vendor_id: str) -> None:
        name = el.get("name", "")
        if not name:
            return
        try:
            code = int(el.get("code", 0))
        except ValueError:
            return

        vendor_id = el.get("vendor-id") or default_vendor_id

        # Determine the raw type name and encoding
        type_el = el.find("type")
        grouped_el = el.find("grouped")
        if type_el is not None:
            raw_type = type_el.get("type-name", "OctetString")
        elif grouped_el is not None:
            raw_type = "Grouped"
        else:
            raw_type = "OctetString"
        encoding = self._resolve_encoding(raw_type)

        # Enum values
        enums: Dict[str, int] = {}
        enum_by_code: Dict[int, str] = {}
        for enum_el in el.findall("enum"):
            ename = enum_el.get("name", "")
            try:
                ecode = int(enum_el.get("code", 0))
            except ValueError:
                continue
            enums[ename] = ecode
            enum_by_code[ecode] = ename

        # Grouped child names (informational)
        grouped_children: List[str] = []
        if grouped_el is not None:
            for gavp_el in grouped_el.findall("gavp"):
                cname = gavp_el.get("name", "")
                if cname:
                    grouped_children.append(cname)

        vendor_code = self._vendor_code(vendor_id)
        avp_def = AVPDef(
            name=name,
            code=code,
            vendor_code=vendor_code,
            vendor_id=vendor_id,
            encoding=encoding,
            raw_type=raw_type,
            mandatory=el.get("mandatory", "may"),
            may_encrypt=el.get("may-encrypt", "no") == "yes",
            protected=el.get("protected", "may"),
            vendor_bit=el.get("vendor-bit", "mustnot"),
            enums=enums,
            enum_by_code=enum_by_code,
            grouped_children=grouped_children,
        )
        # First definition wins (duplicates exist across vendor files)
        self.avp_by_name.setdefault(name, avp_def)
        self.avp_by_code.setdefault((code, vendor_code), avp_def)

    def _resolve_encoding(self, type_name: str) -> str:
        """
        Walk the type-parent chain until a known encoding tag is found.
        Falls back to ``"bytes"`` (OctetString) for unrecognised types.
        """
        current: Optional[str] = type_name
        visited: set = set()
        while current is not None:
            if current in _ENCODING_MAP:
                return _ENCODING_MAP[current]
            if current in visited:
                break
            visited.add(current)
            current = self._type_parent.get(current)
        return "bytes"

    def _vendor_code(self, vendor_id: str) -> int:
        if not vendor_id or vendor_id == "None":
            return 0
        vd = self.vendors.get(vendor_id)
        return vd.code if vd else 0

    # ------------------------------------------------------------------
    # Public lookup API
    # ------------------------------------------------------------------

    def get_avp(self, name: str) -> Optional[AVPDef]:
        """Look up an AVP definition by name."""
        return self.avp_by_name.get(name)

    def get_avp_by_code(
        self, code: int, vendor_code: int = 0
    ) -> Optional[AVPDef]:
        """
        Look up an AVP definition by numeric code and vendor code.

        Falls back to vendor_code=0 when no vendor-specific entry is found,
        which handles cases where the same code is reused with different flags.
        """
        avp = self.avp_by_code.get((code, vendor_code))
        if avp is None and vendor_code != 0:
            avp = self.avp_by_code.get((code, 0))
        return avp

    def get_command(self, name: str) -> Optional[CommandDef]:
        """Look up a command definition by name."""
        return self.commands_by_name.get(name)

    def get_command_by_code(self, code: int) -> Optional[CommandDef]:
        """Look up a command definition by numeric code."""
        return self.commands_by_code.get(code)

    def get_vendor(self, vendor_id: str) -> Optional[VendorDef]:
        """Look up a vendor definition by symbolic ID."""
        return self.vendors.get(vendor_id)

    def get_vendor_by_code(self, code: int) -> Optional[VendorDef]:
        """Look up a vendor definition by numeric code."""
        return self.vendor_by_code.get(code)

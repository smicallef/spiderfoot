# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         detect
# Purpose:      Universal scan target detection for llamaFoot. Takes whatever a
#               user types into a search box and works out what it is.
# -------------------------------------------------------------------------------
"""Universal target detection.

``detect_target`` classifies free-form input into one of the scan target types
that the SpiderFoot engine understands, normalises the value into the form the
engine expects, and reports how confident the guess is and what the other
plausible readings were.

Supported target types and their input shapes:

    ==================  ========================  ===============================
    Engine type         Label                     Example
    ==================  ========================  ===============================
    INTERNET_NAME       Domain Name               example.com
    INTERNET_NAME       Hostname/Sub-domain       abc.example.com
    IP_ADDRESS          IPv4 Address              1.2.3.4
    IPV6_ADDRESS        IPv6 Address              2606:4700:4700::1111
    NETBLOCK_OWNER      Subnet (IPv4)             1.2.3.0/24
    NETBLOCKV6_OWNER    Subnet (IPv6)             2606:4700::/32
    BITCOIN_ADDRESS     Bitcoin Address           1HesYJSP1QqcyPEjnQ9vzBL1wujruNGe7R
    EMAILADDR           E-mail address            bob@example.com
    PHONE_NUMBER        Phone Number              +12345678901
    HUMAN_NAME          Human Name                John Smith
    USERNAME            Username                  jsmith2000
    BGP_AS_OWNER        Network ASN               1234 or AS1234
    ==================  ========================  ===============================

Quotes are optional but, when present, are authoritative: ``"John Smith"`` is
always a name and ``"jsmith2000"`` is always a username.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import typing
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

import phonenumbers
from publicsuffixlist import PublicSuffixList

_psl = PublicSuffixList()

LABELS: typing.Dict[str, str] = {
    "DOMAIN_NAME": "Domain Name",
    "HOSTNAME": "Hostname/Sub-domain",
    "IP_ADDRESS": "IPv4 Address",
    "IPV6_ADDRESS": "IPv6 Address",
    "NETBLOCK_OWNER": "Subnet (IPv4)",
    "NETBLOCKV6_OWNER": "Subnet (IPv6)",
    "BITCOIN_ADDRESS": "Bitcoin Address",
    "EMAILADDR": "E-mail address",
    "PHONE_NUMBER": "Phone Number",
    "HUMAN_NAME": "Human Name",
    "USERNAME": "Username",
    "BGP_AS_OWNER": "Network ASN",
}

# Both DOMAIN_NAME and HOSTNAME are INTERNET_NAME targets for the scan engine.
_ENGINE_TYPE = {"DOMAIN_NAME": "INTERNET_NAME", "HOSTNAME": "INTERNET_NAME"}

_QUOTE_PAIRS = {'"': '"', "'": "'", "“": "”", "‘": "’", "«": "»"}
_LABEL_RX = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$", re.IGNORECASE)
_EMAIL_RX = re.compile(r"^[^\s@\"'<>()\[\],;:\\]{1,64}@([^\s@]+)$")
_ASN_RX = re.compile(r"^(?:asn?\s*)(\d{1,10})$", re.IGNORECASE)
_BARE_DIGITS_RX = re.compile(r"^\d{1,10}$")
_B58_BTC_RX = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_BECH32_BTC_RX = re.compile(r"^bc1[ac-hj-np-z02-9]{8,87}$")
_NAME_TOKEN_RX = re.compile(r"^[^\W\d_]+(?:[.'’-][^\W\d_]+)*\.?$", re.UNICODE)
_USERNAME_RX = re.compile(r"^[\w.\-]{2,64}$", re.UNICODE)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass
class Detection:
    """Result of classifying one piece of user input."""

    ok: bool
    raw: str
    target_type: typing.Optional[str] = None  # engine type, e.g. INTERNET_NAME
    kind: typing.Optional[str] = None  # finer UI kind, e.g. DOMAIN_NAME / HOSTNAME
    label: typing.Optional[str] = None  # human readable label
    value: typing.Optional[str] = None  # normalised value handed to the scanner
    confidence: str = "none"  # high | medium | low | none
    notes: typing.List[str] = field(default_factory=list)
    alternatives: typing.List[typing.Dict[str, str]] = field(default_factory=list)
    error: typing.Optional[str] = None

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return asdict(self)


def _b58check_ok(addr: str) -> bool:
    """Validate a Base58Check encoded Bitcoin address checksum."""
    num = 0
    for ch in addr:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            return False
        num = num * 58 + idx
    raw = num.to_bytes(25, "big") if num.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _strip_quotes(text: str) -> typing.Tuple[str, bool]:
    if len(text) >= 2 and text[0] in _QUOTE_PAIRS and text[-1] == _QUOTE_PAIRS[text[0]]:
        return text[1:-1].strip(), True
    return text, False


def _valid_hostname(host: str) -> typing.Optional[str]:
    """Return the ASCII (punycode) lowercase hostname if syntactically valid and
    under a known public suffix, else None."""
    host = host.strip().rstrip(".").lower()
    if not host or "." not in host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(host) > 253:
        return None
    if not all(_LABEL_RX.match(label) for label in host.split(".")):
        return None
    if host.split(".")[-1].isdigit():
        return None
    if _psl.publicsuffix(host, accept_unknown=False) is None:
        return None
    return host


def _make(raw: str, kind: str, value: str, confidence: str, notes: typing.Optional[typing.List[str]] = None,
          alternatives: typing.Optional[typing.List[typing.Dict[str, str]]] = None) -> Detection:
    return Detection(
        ok=True, raw=raw, target_type=_ENGINE_TYPE.get(kind, kind), kind=kind, label=LABELS[kind],
        value=value, confidence=confidence, notes=notes or [], alternatives=alternatives or [],
    )


def _alt(kind: str, value: str) -> typing.Dict[str, str]:
    return {"kind": kind, "label": LABELS[kind], "target_type": _ENGINE_TYPE.get(kind, kind), "value": value}


def _detect_phone(text: str, default_region: typing.Optional[str]) -> typing.Optional[Detection]:
    cleaned = re.sub(r"[\s().\-]", "", text)
    if cleaned.startswith("00") and cleaned[2:].isdigit():
        cleaned = "+" + cleaned[2:]
    if not re.fullmatch(r"\+\d{6,15}", cleaned):
        return None
    try:
        num = phonenumbers.parse(cleaned, None)
    except phonenumbers.NumberParseException:
        return Detection(ok=False, raw=text, error="Phone number could not be parsed. Use E.164 format, e.g. +12345678901.")
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    if phonenumbers.is_valid_number(num):
        return _make(text, "PHONE_NUMBER", e164, "high")
    if phonenumbers.is_possible_number(num):
        return _make(text, "PHONE_NUMBER", e164, "medium", ["Length is plausible but the number is not in a known numbering plan range."])
    return _make(text, "PHONE_NUMBER", e164, "low", ["Number does not look valid for its country code."])


def detect_target(raw: typing.Optional[str], default_region: typing.Optional[str] = None) -> Detection:
    """Work out what a piece of user input is.

    Args:
        raw: whatever the user typed
        default_region: unused for now, reserved for national format phone numbers

    Returns:
        Detection: ``ok`` is False when nothing sensible could be derived, with
        ``error`` explaining why.
    """
    if not isinstance(raw, str) or not raw.strip():
        return Detection(ok=False, raw=raw or "", error="Enter something to search for.")

    original = raw
    text = raw.strip()
    notes: typing.List[str] = []

    # 1. Quotes are an explicit statement of intent: a name or a username.
    inner, quoted = _strip_quotes(text)
    if quoted:
        if not inner:
            return Detection(ok=False, raw=original, error="Nothing inside the quotes.")
        if re.search(r"\s", inner):
            return _make(original, "HUMAN_NAME", re.sub(r"\s+", " ", inner), "high")
        return _make(original, "USERNAME", inner, "high")

    # 2. Unwrap common wrappers: mailto:, <bob@x.com>, "Name <bob@x.com>", @handles come later.
    lowered = text.lower()
    if lowered.startswith("mailto:"):
        text = text[7:].strip()
        notes.append("Removed mailto: prefix.")
    angle = re.search(r"<([^<>\s]+@[^<>\s]+)>\s*$", text)
    if angle:
        text = angle.group(1)
        notes.append("Used the address inside angle brackets.")

    # 3. Phone numbers (explicit + or 00 international prefix).
    if re.match(r"^(\+|00)[\d\s().\-]+$", text):
        phone = _detect_phone(text, default_region)
        if phone is not None:
            phone.notes = notes + phone.notes
            return phone

    # 4. URLs: pull out the host and classify that.
    if "://" in text or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}[:/]", text, re.IGNORECASE) and ("/" in text or "?" in text):
        candidate = text if "://" in text else "//" + text
        try:
            host = urlsplit(candidate).hostname
        except ValueError:
            host = None
        if host:
            inner_result = detect_target(host, default_region)
            if inner_result.ok:
                inner_result.raw = original
                inner_result.notes = notes + ["Extracted the host from a URL."] + inner_result.notes
                return inner_result

    # 5. IP addresses and subnets.
    ip_text = text.strip("[]")
    ip_text = re.sub(r"%[\w.\-]+$", "", ip_text)  # IPv6 zone id
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$", ip_text)
    if m:
        ip_text = m.group(1)
        notes.append("Ignored the port number.")
    if "/" in ip_text:
        try:
            net = ipaddress.ip_network(ip_text, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if str(net) != ip_text.lower():
                notes.append(f"Host bits were set; using the network address {net}.")
            kind = "NETBLOCK_OWNER" if net.version == 4 else "NETBLOCKV6_OWNER"
            if (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 48):
                notes.append("This is a very large network; a scan will be slow and noisy.")
            return _make(original, kind, str(net), "high", notes)
    else:
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            ip = None
        if ip is not None:
            kind = "IP_ADDRESS" if ip.version == 4 else "IPV6_ADDRESS"
            return _make(original, kind, str(ip), "high", notes)

    # 6. E-mail addresses.
    em = _EMAIL_RX.match(text)
    if em:
        domain = _valid_hostname(em.group(1))
        if domain:
            local = text.rsplit("@", 1)[0]
            return _make(original, "EMAILADDR", f"{local}@{domain}".lower(), "high", notes)

    # 7. Autonomous system numbers.
    asn = _ASN_RX.match(text)
    if asn:
        return _make(original, "BGP_AS_OWNER", str(int(asn.group(1))), "high", notes)

    # 8. Bitcoin addresses.
    if _B58_BTC_RX.match(text):
        if _b58check_ok(text):
            return _make(original, "BITCOIN_ADDRESS", text, "high", notes)
        return _make(original, "BITCOIN_ADDRESS", text, "low",
                     notes + ["Looks like a Bitcoin address but the checksum is invalid. Check for typos."],
                     [_alt("USERNAME", text)])
    btc = text if text.islower() else text.lower() if text.isupper() else ""
    if btc and _BECH32_BTC_RX.match(btc):
        return _make(original, "BITCOIN_ADDRESS", btc, "high", notes)

    # 9. Bare digits: an ASN unless it is clearly a phone number missing its "+".
    if _BARE_DIGITS_RX.match(text) and int(text) <= 4294967295 and not text.startswith("0"):
        alts: typing.List[typing.Dict[str, str]] = []
        if len(text) >= 8:
            try:
                num = phonenumbers.parse("+" + text, None)
                if phonenumbers.is_valid_number(num):
                    alts.append(_alt("PHONE_NUMBER", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)))
            except phonenumbers.NumberParseException:
                pass
        conf = "medium" if alts else "high"
        if alts:
            notes.append("Digits only: read as an ASN. Add a leading + to search it as a phone number.")
        return _make(original, "BGP_AS_OWNER", str(int(text)), conf, notes, alts)
    if re.fullmatch(r"\d{8,15}", text):
        phone = _detect_phone("+" + text, default_region)
        if phone is not None and phone.ok:
            phone.raw = original
            phone.notes = notes + ["No leading +; assumed an international number."] + phone.notes
            phone.confidence = "low" if phone.confidence != "high" else "medium"
            return phone

    # 10. Domains and hostnames.
    host = _valid_hostname(text)
    if host:
        registrable = _psl.privatesuffix(host)
        alts = []
        if _USERNAME_RX.match(text) and "." in text:
            alts.append(_alt("USERNAME", text))
        if registrable is None or registrable == host:
            return _make(original, "DOMAIN_NAME", host, "high" if registrable else "medium", notes, alts)
        return _make(original, "HOSTNAME", host, "high", notes, alts)

    # 11. Names and usernames without quotes.
    if re.search(r"\s", text):
        tokens = text.split()
        if 2 <= len(tokens) <= 6 and all(_NAME_TOKEN_RX.match(t) for t in tokens):
            return _make(original, "HUMAN_NAME", " ".join(tokens), "high", notes)
        if 2 <= len(tokens) <= 6 and not any(c in text for c in "@/\\:"):
            return _make(original, "HUMAN_NAME", " ".join(tokens), "low",
                         notes + ["Contains digits or symbols; treated as a name. Quote it to be explicit."])
        return Detection(ok=False, raw=original, error="Could not tell what this is. Try one item at a time.")

    handle = text[1:] if text.startswith("@") else text
    if _USERNAME_RX.match(handle):
        if handle is not text:
            notes.append("Removed the leading @.")
        return _make(original, "USERNAME", handle, "medium", notes + ["Treated as a username. Quote it to be explicit."])

    return Detection(ok=False, raw=original, error="Could not tell what this is. Supported: domain, hostname, IPv4/IPv6, subnet, ASN, e-mail, phone (+E.164), Bitcoin address, name, username.")

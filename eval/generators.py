"""Synthetic PII and clean-text generators for the detector eval.

Every PII generator returns a value that is valid for its format (checksums
included) in a randomly chosen surface form. Clean generators return text a
tool result plausibly contains and that is *not* personal data. Nothing here
imports ``pii_mcp``: the eval must not share logic with the code it scores.
"""

from __future__ import annotations

import ipaddress
import random
import string
import uuid
from collections.abc import Callable

R = random.Random  # every generator takes the caller's seeded RNG


def _digits(r: R, n: int) -> str:
    return "".join(r.choice(string.digits) for _ in range(n))


def _luhn_complete(body: str) -> str:
    """Append the Luhn check digit to ``body``."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def _group(value: str, sizes: tuple[int, ...], sep: str) -> str:
    out, i = [], 0
    for size in sizes:
        out.append(value[i : i + size])
        i += size
    return sep.join(out)


# --- PII -------------------------------------------------------------------


def email(r: R) -> str:
    first = r.choice(["ada", "jan", "maria", "li", "o.brien", "anne-marie", "j", "sam"])
    last = r.choice(["lovelace", "devries", "garcia", "wang", "smith", "", "99", "k"])
    local = first + r.choice([".", "_", "", "+tag."]) + last if last else first
    domain = r.choice(["example.com", "mail.example.org", "corp.example.co.uk", "ex.io", "uni.example.nl"])
    value = f"{local}@{domain}"
    return value.upper() if r.random() < 0.05 else value


_IBAN_BBAN: dict[str, Callable[[R], str]] = {
    "NL": lambda r: "".join(r.choice(string.ascii_uppercase) for _ in range(4)) + _digits(r, 10),
    "DE": lambda r: _digits(r, 18),
    "GB": lambda r: "".join(r.choice(string.ascii_uppercase) for _ in range(4)) + _digits(r, 14),
    "BE": lambda r: _digits(r, 12),
    "FR": lambda r: _digits(r, 23),
}


def iban(r: R) -> str:
    country = r.choice(list(_IBAN_BBAN))
    bban = _IBAN_BBAN[country](r)
    numeric = "".join(str(int(c, 36)) for c in bban + country + "00")
    compact = f"{country}{98 - int(numeric) % 97:02d}{bban}"
    style = r.random()
    if style < 0.4:
        return compact
    grouped = " ".join(compact[i : i + 4] for i in range(0, len(compact), 4))
    if style < 0.8:
        return grouped
    if style < 0.9:
        return grouped.lower()
    return grouped.replace(" ", "-")


# (prefix, total length, groupings)
_CARDS = [
    ("4", 16, [(4, 4, 4, 4)]),
    ("51", 16, [(4, 4, 4, 4)]),
    ("2221", 16, [(4, 4, 4, 4)]),
    ("6011", 16, [(4, 4, 4, 4)]),
    ("35", 16, [(4, 4, 4, 4)]),
    ("34", 15, [(4, 6, 5)]),
    ("37", 15, [(4, 6, 5)]),
    ("36", 14, [(4, 6, 4)]),
    ("4", 13, [(4, 4, 5)]),
    ("50", 17, [(4, 4, 4, 4, 1)]),
    ("62", 18, [(4, 4, 4, 4, 2)]),
    ("62", 19, [(4, 4, 4, 4, 3)]),
    ("4", 19, [(4, 4, 4, 4, 3)]),
]


def credit_card(r: R) -> str:
    prefix, length, groupings = r.choice(_CARDS)
    number = _luhn_complete(prefix + _digits(r, length - len(prefix) - 1))
    if r.random() < 0.35:
        return number
    return _group(number, r.choice(groupings), r.choice([" ", " ", "-", "."]))


def mac(r: R) -> str:
    octets = [f"{r.randrange(256):02x}" for _ in range(6)]
    style = r.random()
    if style < 0.45:
        value = ":".join(octets)
    elif style < 0.7:
        value = "-".join(octets)
    elif style < 0.85:
        joined = "".join(octets)
        value = ".".join(joined[i : i + 4] for i in (0, 4, 8))
    else:
        value = ".".join(octets)
    return value.upper() if r.random() < 0.3 else value


def imei(r: R) -> str:
    number = _luhn_complete(r.choice(["35", "01", "86", "49"]) + _digits(r, 12))
    sep = r.choice(["-", " ", "/"])
    if r.random() < 0.5:
        return _group(number, (2, 6, 6, 1), sep)
    return _group(number, (8, 6, 1), sep)


def ip(r: R) -> str:
    style = r.random()
    v4 = ipaddress.IPv4Address(r.randrange(0x01000000, 0xDF000000))
    if style < 0.45:
        return str(v4)
    v6 = ipaddress.IPv6Address(r.getrandbits(128))
    if style < 0.65:
        return v6.compressed
    if style < 0.75:
        return v6.exploded
    if style < 0.85:  # compressed with a zero run
        hextets = v6.exploded.split(":")[:3] + ["0"] * 4 + [f"{r.randrange(1, 0xFFFF):x}"]
        return str(ipaddress.IPv6Address(":".join(hextets)))
    return r.choice(["::ffff:", "64:ff9b::"]) + str(v4)


def location(r: R) -> str:
    while True:
        lat = r.uniform(-85, 85)
        lon = r.uniform(-179, 179)
        if abs(lat) > 1.5 or abs(lon) > 1.5:
            break
    places = r.randint(4, 6)
    style = r.random()
    if style < 0.6:
        return f"{lat:.{places}f}{r.choice([', ', ','])}{lon:.{places}f}"
    ns, ew = ("N" if lat >= 0 else "S"), ("E" if lon >= 0 else "W")
    return f"{abs(lat):.{places}f}° {ns}, {abs(lon):.{places}f}° {ew}"


def bsn(r: R) -> str:
    while True:
        body = _digits(r, 8)
        total = sum(int(d) * w for d, w in zip(body, range(9, 1, -1)))
        check = total % 11
        if check < 10 and body != "00000000":
            number = body + str(check)
            break
    style = r.random()
    if style < 0.6:
        return number
    return _group(number, (3, 3, 3), r.choice([".", " ", "-"]))


def ssn(r: R) -> str:
    area = r.choice([a for a in range(1, 900) if a != 666])
    number = f"{area:03d}{r.randint(1, 99):02d}{r.randint(1, 9999):04d}"
    style = r.random()
    if style < 0.6:
        return _group(number, (3, 2, 4), "-")
    if style < 0.8:
        return _group(number, (3, 2, 4), " ")
    return number


def itin(r: R) -> str:
    """A grouped US ITIN: ``9XX-XX-XXXX`` with a group the IRS issues.

    Groups 50–65, 70–88, 90–92 and 94–99 (IRM 3.21.263). Only the hyphen and
    space groupings are emitted: the detector leaves the compact form alone.
    """
    group = r.choice([*range(50, 66), *range(70, 89), 90, 91, 92, *range(94, 100)])
    number = f"9{r.randint(0, 99):02d}{group:02d}{r.randint(0, 9999):04d}"
    return _group(number, (3, 2, 4), r.choice(["-", " "]))


def tax_id_de(r: R) -> str:
    while True:
        pool = list(string.digits)
        r.shuffle(pool)
        body = pool[:9]
        body.insert(r.randrange(1, 10), body[r.randrange(9)])  # one digit twice
        if body[0] == "0":
            continue
        product = 10
        for ch in body:
            total = (int(ch) + product) % 10 or 10
            product = (2 * total) % 11
        check = 11 - product
        return "".join(body) + str(0 if check == 10 else check)


def vat_nl(r: R) -> str:
    value = f"NL{_digits(r, 9)}B{_digits(r, 2)}"
    return value if r.random() < 0.7 else f"NL {value[2:11]} B{value[12:]}"


def vat_de(r: R) -> str:
    body = str(r.randint(1, 9)) + _digits(r, 7)
    product = 10
    for digit in body:
        total = (int(digit) + product) % 10 or 10
        product = (2 * total) % 11
    value = body + str((11 - product) % 10)
    style = r.random()
    if style < 0.5:
        return f"DE{value}"
    sep = " " if style < 0.85 else "."
    return "DE" + sep + _group(value, (3, 3, 3), sep)


def passport_nl(r: R) -> str:
    letters = string.ascii_uppercase.replace("O", "")
    alnum = letters + string.digits
    return (
        "".join(r.choice(letters) for _ in range(2))
        + "".join(r.choice(alnum) for _ in range(6))
        + r.choice(string.digits)
    )


def phone_nl(r: R) -> str:
    mobile = "6" + _digits(r, 8)
    return r.choice(
        [
            f"06-{mobile[1:]}",
            f"06 {mobile[1:5]} {mobile[5:]}",
            f"0{mobile}",
            f"+31 6 {mobile[1:]}",
            f"+31{mobile}",
            f"+31 (0)6 {mobile[1:]}",
            f"020 {_digits(r, 3)} {_digits(r, 4)}",
            f"010-{_digits(r, 7)}",
        ]
    )


def phone_en(r: R) -> str:
    area = f"{r.randint(2, 9)}{_digits(r, 2)}"
    exch = f"{r.randint(2, 9)}{_digits(r, 2)}"
    line = _digits(r, 4)
    return r.choice(
        [
            f"({area}) {exch}-{line}",
            f"{area}-{exch}-{line}",
            f"{area}.{exch}.{line}",
            f"+1 {area} {exch} {line}",
            f"1-{area}-{exch}-{line}",
        ]
    )


def phone_de(r: R) -> str:
    area = r.choice(["30", "40", "89", "221", "69"])
    sub = _digits(r, 10 - len(area) - 1 + r.randint(0, 1))
    return r.choice([f"0{area} {sub}", f"0{area}/{sub}", f"+49 {area} {sub}"])


def phone_intl(r: R) -> str:
    return r.choice(
        [
            f"+44 20 {_digits(r, 4)} {_digits(r, 4)}",
            f"+33 1 {_digits(r, 2)} {_digits(r, 2)} {_digits(r, 2)} {_digits(r, 2)}",
            f"+32 2 {_digits(r, 3)} {_digits(r, 2)} {_digits(r, 2)}",
            f"0044 20 {_digits(r, 4)} {_digits(r, 4)}",
        ]
    )


_FORBIDDEN_PAIRS = ("SA", "SD", "SS")


def _letters(r: R, n: int) -> str:
    while True:
        value = "".join(r.choice("BDFGHJKLNPRSTVXZ") for _ in range(n))
        if not any(p in value for p in _FORBIDDEN_PAIRS):
            return value


def postcode_nl(r: R) -> str:
    return f"{r.randint(1000, 9999)}{r.choice([' ', ''])}{_letters(r, 2)}"


# Copied, not imported: the eval must not share logic with the code it scores.
_UK_POSTCODE_AREAS = (
    "AB AL B BA BB BD BH BL BN BR BS BT CA CB CF CH CM CO CR CT CV CW DA DD DE DG DH "
    "DL DN DT DY E EC EH EN EX FK FY G GL GU GY HA HD HG HP HR HS HU HX IG IM IP IV JE "
    "KA KT KW KY L LA LD LE LL LN LS LU M ME MK ML N NE NG NN NP NR NW OL OX PA PE PH "
    "PL PO PR QC RG RH RM S SA SE SG SK SL SM SN SO SP SR SS ST SW SY TA TD TF TN TQ TR "
    "TS TW UB W WA WC WD WF WN WR WS WV YO ZE"
).split()


def postcode_uk(r: R) -> str:
    if r.random() < 0.02:
        return "GIR 0AA"
    district = r.randint(1, 99)
    outward = f"{r.choice(_UK_POSTCODE_AREAS)}{district}"
    if district < 10 and r.random() < 0.25:  # EC1A; never AB12C
        outward += r.choice(string.ascii_uppercase)
    inward = r.choice(string.digits) + "".join(
        r.choice("ABDEFGHJLNPQRSTUWXYZ") for _ in range(2)
    )
    return f"{outward} {inward}"


def license_plate_nl(r: R) -> str:
    d = lambda n: _digits(r, n)  # noqa: E731
    value = r.choice(
        [
            f"{_letters(r, 2)}-{d(2)}-{_letters(r, 2)}",
            f"{d(2)}-{_letters(r, 3)}-{d(1)}",
            f"{d(1)}-{_letters(r, 3)}-{d(2)}",
            f"{_letters(r, 2)}-{d(3)}-{_letters(r, 1)}",
            f"{_letters(r, 3)}-{d(2)}-{_letters(r, 1)}",
        ]
    )
    return value.lower() if r.random() < 0.1 else value


def _house_number(r: R) -> str:
    number = str(r.randint(1, 999))
    return number + r.choice(["", "", "", "a", "B", "-2", "/1"])


def _number_gap(r: R) -> str:
    """Separator between a street and its house number.

    A comma carries at least one space: a comma with none behind it is a CSV
    field separator, not address punctuation.
    """
    return r.choice([" ", " ", " ", ", ", ",  ", ",\u00a0"])


def street_nl(r: R) -> str:
    name = r.choice(["Kerk", "Molen", "Dorps", "Stations", "Van Baerle", "Prinsen", "Keizers", "Hoofd", "Sint-Jans", "Oranje"])
    kind = r.choice(["straat", "laan", "weg", "gracht", "plein", "kade", "singel", "dijk", "steeg", "markt", "hof", "pad"])
    glued = f"{name}{kind}"
    spaced = f"{r.choice(['Grote', 'Oude', 'Nieuwe', 'Korte'])} {r.choice(['Markt', 'Gracht', 'Kade', 'Haven'])}"
    prefixed = f"{r.choice(['Laan', 'Weg', 'Plein'])} {r.choice(['van', 'van de', 'op'])} {r.choice(['Meerdervoort', 'Nieuw Oost-Indië', 'Zuid'])}"
    return f"{r.choice([glued, glued, glued, spaced, prefixed])}{_number_gap(r)}{_house_number(r)}"


def street_de(r: R) -> str:
    glued = f"{r.choice(['Haupt', 'Bahnhof', 'Schiller', 'Goethe', 'Garten', 'Linden', 'Kirch'])}{r.choice(['straße', 'strasse', 'str.', 'weg', 'allee', 'platz', 'gasse', 'ufer', 'ring'])}"
    spaced = f"{r.choice(['Berliner', 'Frankfurter', 'Kölner', 'Neuer', 'Alter'])} {r.choice(['Straße', 'Str.', 'Allee', 'Weg', 'Ring'])}"
    return f"{r.choice([glued, glued, spaced])}{_number_gap(r)}{_house_number(r)}"


def street_en(r: R) -> str:
    name = r.choice(["Baker", "High", "Church", "Station", "Oxford", "Victoria", "Old Kent", "Mill", "Pennsylvania", "Park"])
    kind = r.choice(["Street", "Road", "Lane", "Avenue", "Drive", "Close", "Way", "St", "Rd.", "Ave"])
    number = f"{r.randint(1, 9999)}{r.choice(['', '', 'B'])}"
    return f"{number}{_number_gap(r)}{name} {kind}"


_NAMES = {
    "en": (["Ada", "John", "Emily", "Michael", "Sarah", "James"], ["Lovelace", "Smith", "Johnson", "Brown", "Taylor", "Wilson"]),
    "nl": (["Jan", "Pieter", "Sanne", "Emma", "Daan", "Lotte"], ["de Vries", "Jansen", "van den Berg", "Bakker", "Visser", "de Jong"]),
    "de": (["Anna", "Lukas", "Sophie", "Felix", "Marie", "Jonas"], ["Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Becker"]),
}


def _person(lang: str) -> Callable[[R], str]:
    first, last = _NAMES[lang]

    def gen(r: R) -> str:
        return f"{r.choice(first)} {r.choice(last)}"

    gen.__name__ = f"person_{lang}"
    return gen


# (category, generator, languages the detector needs). ``person`` needs the
# NER pass and is only scored by ``score.py --ner``.
PII: list[tuple[str, Callable[[R], str], tuple[str, ...]]] = [
    ("email", email, ()),
    ("iban", iban, ()),
    ("credit_card", credit_card, ()),
    ("mac", mac, ()),
    ("imei", imei, ()),
    ("ip", ip, ()),
    ("location", location, ()),
    ("bsn", bsn, ("nl",)),
    ("ssn", ssn, ("en",)),
    ("tax_id", tax_id_de, ("de",)),
    ("tax_id", itin, ("en",)),
    ("vat_id", vat_nl, ("nl",)),
    ("vat_id", vat_de, ("de",)),
    ("passport", passport_nl, ("nl",)),
    ("phone", phone_nl, ("nl",)),
    ("phone", phone_en, ("en",)),
    ("phone", phone_de, ("de",)),
    ("phone", phone_intl, ("en",)),
    ("address", postcode_nl, ("nl",)),
    ("address", postcode_uk, ("en",)),
    ("address", street_nl, ("nl",)),
    ("address", street_en, ("en",)),
    ("address", street_de, ("de",)),
    ("license_plate", license_plate_nl, ("nl",)),
    ("person", _person("en"), ()),
    ("person", _person("nl"), ()),
    ("person", _person("de"), ()),
]


# --- Clean -----------------------------------------------------------------


def _isbn13(r: R) -> str:
    body = r.choice(["978", "979"]) + _digits(r, 9)
    total = sum(int(d) * (1 if i % 2 == 0 else 3) for i, d in enumerate(body))
    return body + str((10 - total % 10) % 10)


def _ean13(r: R) -> str:
    body = r.choice(["87", "40", "50", "30", "80"]) + _digits(r, 10)
    total = sum(int(d) * (1 if i % 2 == 0 else 3) for i, d in enumerate(body))
    return body + str((10 - total % 10) % 10)


CLEAN: list[tuple[str, Callable[[R], str]]] = [
    ("vat_de_bad_checksum", lambda r: "DE136695977"),
    ("vat_de_leading_zero", lambda r: "DE036695976"),
    ("uuid", lambda r: str(uuid.UUID(int=r.getrandbits(128), version=4))),
    ("sha256", lambda r: f"{r.getrandbits(256):064x}"),
    ("git_sha", lambda r: f"commit {r.getrandbits(160):040x}"),
    ("iso_time", lambda r: f"2024-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}.{_digits(r, 3)}Z"),
    ("unix_s", lambda r: str(r.randint(1_500_000_000, 1_800_000_000))),
    ("unix_ms", lambda r: str(r.randint(1_500_000_000_000, 1_800_000_000_000))),
    ("snowflake", lambda r: str(r.randint(10**17, 2 * 10**18))),
    ("semver", lambda r: f"v{r.randint(0, 20)}.{r.randint(0, 40)}.{r.randint(0, 99)}"),
    ("embedding", lambda r: "[" + ", ".join(f"{r.uniform(-1, 1):.{r.randint(4, 8)}f}" for _ in range(r.randint(4, 12))) + "]"),
    ("isbn13", _isbn13),
    ("ean13", _ean13),
    ("price", lambda r: r.choice([f"€ {r.randint(1, 9999)},{_digits(r, 2)}", f"${r.randint(1, 999)}.{_digits(r, 2)}", f"{r.randint(1, 99)}.{_digits(r, 2)} EUR"])),
    ("duration", lambda r: f"took {r.randint(1, 9999)}ms ({r.uniform(0, 100):.1f}%)"),
    ("hex_color", lambda r: f"color: #{r.getrandbits(24):06x};"),
    ("file_pos", lambda r: f"src/app/handlers.py:{r.randint(1, 2000)}:{r.randint(1, 120)}"),
    ("clock", lambda r: f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}"),
    ("k8s", lambda r: f"cpu: {r.randint(50, 4000)}m, memory: {r.choice([128, 256, 512, 1024])}Mi, replicas: {r.randint(1, 20)}"),
    ("http_log", lambda r: f'"GET /api/v{r.randint(1, 3)}/items/{r.randint(1, 99999)} HTTP/1.1" {r.choice([200, 201, 404, 500])} {r.randint(100, 99999)}'),
    ("base64", lambda r: "".join(r.choice(string.ascii_letters + string.digits + "+/") for _ in range(r.randint(20, 44)))),
    ("order_ref", lambda r: f"ORD-{r.randint(2019, 2026)}-{r.randint(1, 999999):06d}"),
    ("stats", lambda r: f"p50={r.uniform(0, 500):.3f}ms p99={r.uniform(0, 5000):.3f}ms n={r.randint(10, 100000)}"),
    ("coord_like", lambda r: f"scale {r.uniform(-1, 1):.4f}, {r.uniform(-1, 1):.4f}"),
    ("street_word_en", lambda r: r.choice(["The Park 12 tickets", "Theme Park 2 opens", "Safe Haven 3 is out"])),
    ("street_name", lambda r: r.choice(["Kerkstraat", "Baker Street", "Hauptstraße", "Frankfurter Allee", "de Prinsengracht", "Oxford Road"])),
    ("company", lambda r: f"{r.choice(['Philips', 'Albert Heijn', 'Siemens', 'Baker & Co', 'Van Dijk Bouw BV'])} {r.choice(['Q3', 'report', '2024', 'team'])}"),
    ("city_year", lambda r: f"{r.choice(['Amsterdam', 'Rotterdam', 'Berlin', 'London'])} {r.randint(1990, 2030)}"),
    ("date", lambda r: r.choice([f"{r.randint(1, 28):02d}-{r.randint(1, 12):02d}-{r.randint(1990, 2030)}", f"{r.randint(1990, 2030)}/{r.randint(1, 12):02d}/{r.randint(1, 28):02d}"])),
    # Postcode-shaped, but not a real area.
    ("uk_postcode_product", lambda r: r.choice(["A4 2PK", "PS5 1TB", "A1 2PK"])),
    # ITIN-shaped, but group 89 / 93 (other TINs) or outside the ITIN ranges.
    ("itin_shaped", lambda r: f"9{_digits(r, 2)}-{r.choice(['89', '93', '40', '69'])}-{_digits(r, 4)}"),
]

# Clean text that looks like PII to any pattern matcher (bare 9-digit ids vs
# BSN/SSN, a number before a real street word). Reported, not scored: flipping
# these trades recall for precision.
AMBIGUOUS: list[tuple[str, Callable[[R], str]]] = [
    ("nine_digit_id", lambda r: f"invoice {r.randint(100_000_000, 999_999_999)}"),
    ("semver4", lambda r: f"{r.randint(1, 9)}.{r.randint(0, 9)}.{r.randint(0, 9)}.{r.randint(0, 9)}"),
    ("suffix_word", lambda r: r.choice(["Use the Keypad 3 times", "Open Notepad 2 now", "Supermarkt 24 uur open", "Gerechtshof 2 oordeelde", "Der Käufer 2 zahlt"])),
    ("street_word_phrase", lambda r: r.choice(["Chapter 12 Main Street", "In 2024 Times Square was busy", "I bought 2 Hard Drive units", "Parkplatz 12 ist frei"])),
    ("decimal_pair", lambda r: f"{r.uniform(2, 80):.4f}, {r.uniform(2, 80):.4f}"),
    # SSD sizes that are also valid postcodes; masked.
    ("uk_postcode_ambiguous", lambda r: r.choice(["M2 1TB", "M2 2TB", "M1 1TB"])),
    # A comma before the house number masks like the comma-less form already
    # does: a chapter, a section, a year, or a version next to a street word.
    ("street_word_comma", lambda r: r.choice(["Chapter 12, Main Street", "Sections 3, Park Lane and 4", "Kerkstraat, 2024", "v1.2, Park Lane"])),
]


# --- Contexts --------------------------------------------------------------

# The single ``{}`` is replaced by the value (plain substitution, so other
# braces are literal). None of these may contain PII themselves.
TEMPLATES: list[str] = [
    "{}",
    "Contact: {}",
    "value={} status=ok",
    '{"field": "{}", "active": true}',
    "id,{},2024-01-15,active",
    "| user | {} |",
    "See ({}) for details.",
    "<td>{}</td>",
    "[INFO] 2024-01-15T10:30:00Z request from {} accepted",
    "- {}\n- next item",
    "key: '{}'",
    "Please update {}, thanks!",
    "log line\n{}\nend",
    "user:{} role=admin",
    "prefix\t{}\tsuffix",
]

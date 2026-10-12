import re

IP_PATTERN = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
FLAG_BITS = [(1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"), (32, "URG")]


def clean(v):
    s = str(v).strip()
    return None if s in ("", "0", "0.0", "nan") else s


def num(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if x != x else x


def decode_flags(v):
    n = int(num(v))
    return ",".join(name for bit, name in FLAG_BITS if n & bit)


def decode_payload(v, limit=150):
    s = clean(v)
    if s is None or len(s) < 8 or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    raw = bytes.fromhex(s)
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw)
    if printable / len(raw) < 0.8:
        return None
    text = raw.decode("latin-1")
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^\x20-\x7e]", "", text).strip()
    return text[:limit] or None


if __name__ == "__main__":
    print(clean("0.0"), clean("POST"))
    print(decode_flags(24.0))
    print(decode_payload("474554202f20485454502f312e310d0a"))
    print(decode_payload("785383bf379b49ee"))
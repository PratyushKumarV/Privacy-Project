import re
import pandas as pd
from textify import IP_PATTERN, clean, num, decode_flags, decode_payload

PRIVATE = re.compile(r"(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


def valid_ip(v):
    s = str(v).strip()
    return s if IP_PATTERN.fullmatch(s) else None


def is_external(ip):
    return ip is not None and not PRIVATE.match(ip)


def valid_port(v):
    n = num(v)
    return int(n) if 0 < n <= 65535 else None


def short(v, limit=150):
    s = clean(v)
    if s is None:
        return None
    s = s.replace("\\n", " ").replace("\\r", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit] or None


def row_to_text(row, use_ips=True):
    parts = []

    src = valid_ip(row["ip.src_host"])
    dst = valid_ip(row["ip.dst_host"]) or valid_ip(row["frame.time"])
    sport = valid_port(row["tcp.srcport"])
    dport = valid_port(row["tcp.dstport"])
    flags = decode_flags(row["tcp.flags"])
    tcp_len = int(num(row["tcp.len"]))
    udp_port = valid_port(row["udp.port"])

    raw_sport = clean(row["tcp.srcport"])
    service = raw_sport if raw_sport and not re.fullmatch(r"[\d.]+", raw_sport) else None

    if num(row["icmp.checksum"]) or num(row["icmp.seq_le"]):
        proto = "ICMP"
    elif num(row["arp.opcode"]):
        proto = "ARP"
    elif num(row["udp.stream"]) or num(row["udp.time_delta"]) or udp_port:
        proto = "UDP"
    elif sport or dport or flags:
        proto = "TCP"
    else:
        proto = "Network"

    line = f"{proto} packet"
    if use_ips:
        if src and dst:
            line += f" from {src} to {dst}"
        elif src or dst:
            line += f" involving {src or dst}"
        else:
            line += " with no valid IP header"
        if is_external(src):
            line += " (source outside the local network)"
        if is_external(dst):
            line += " (destination outside the local network)"
    if proto == "TCP":
        if sport and dport:
            line += f", port {sport} to port {dport}"
        elif dport:
            line += f", to port {dport}"
        if flags:
            line += f", flags {flags}"
        if tcp_len:
            line += f", {tcp_len} bytes of data"
    elif proto == "UDP" and udp_port:
        line += f", port {udp_port}"
    parts.append(line + ".")

    if service:
        parts.append(f"Service name in packet: {service}.")

    method = clean(row["http.request.method"])
    uri = clean(row["http.request.full_uri"])
    version = clean(row["http.request.version"])
    if method or uri:
        parts.append("HTTP request: " + " ".join(x for x in (method, uri, version) if x) + ".")
    if num(row["http.response"]):
        parts.append("HTTP response.")
    query = short(row["http.request.uri.query"])
    if query:
        parts.append(f"Query string: {query}.")
    body = short(row["http.file_data"])
    if body:
        parts.append(f"HTTP body: {body}.")
    referer = short(row["http.referer"])
    if referer:
        parts.append(f"Referer: {referer}.")

    topic = short(row["mqtt.topic"])
    msg = short(row["mqtt.msg"])
    if topic or msg:
        parts.append(f"MQTT message, topic {topic or 'unknown'}, content {msg or 'none'}.")

    payload = decode_payload(row["tcp.payload"])
    if payload:
        parts.append(f"Payload text: {payload}")

    return " ".join(parts)


if __name__ == "__main__":
    df = pd.read_csv("data/test.csv", low_memory=False).sample(3000, random_state=1)
    df["text"] = df.apply(row_to_text, axis=1)

    for label, g in df.groupby("Attack_type"):
        print(f"--- {label} ---")
        print(g["text"].iloc[0])
        print()
    print("Average length:", int(df["text"].str.len().mean()), "characters")
import json
import time
from collections import Counter
import re

import chromadb
import joblib
import pandas as pd
from sentence_transformers import SentenceTransformer
from textify import decode_flags    

from describe import row_to_text, valid_port
from llm import generate
from train_classifier import make_features

K = 5
SCHEMA = '{"explanation": "2-3 sentences citing evidence visible in the log"}'
HEADER_ONLY_OK = {"Normal", "DDoS_ICMP", "DDoS_UDP", "DDoS_TCP", "MITM"}
EVIDENCE_WORDS = ("Payload text", "HTTP", "MQTT", "Service name")

_bundle = joblib.load("models/clf_robust.joblib")
_embedder = SentenceTransformer("all-MiniLM-L6-v2")
_db = chromadb.PersistentClient(path="chroma_db")
_examples = _db.get_collection("examples")
_kb = _db.get_collection("mitigations")


def classify(row):
    X = make_features(pd.DataFrame([row]))[_bundle["columns"]]
    probs = _bundle["model"].predict_proba(X)[0]
    ranked = sorted(zip(_bundle["model"].classes_, probs), key=lambda p: p[1], reverse=True)
    return [(str(c), float(p)) for c, p in ranked[:3]]


def retrieve_examples(text, predicted):
    emb = _embedder.encode([text]).tolist()
    overall = _examples.query(query_embeddings=emb, n_results=K)
    votes = [m["attack_type"] for m in overall["metadatas"][0]]
    same = _examples.query(query_embeddings=emb, n_results=3, where={"attack_type": predicted})
    return votes, same["documents"][0]


def retrieve_knowledge(text, predicted):
    emb = _embedder.encode([text]).tolist()
    res = _kb.query(query_embeddings=emb, n_results=6, where={"attack_type": predicted})
    return list(zip(res["documents"][0], res["metadatas"][0]))

def ungrounded_numbers(explanation, log_text):
    cleaned = re.sub(r"CAPEC-\d+", "", explanation)
    nums = set(re.findall(r"\d+", cleaned))
    return sorted(n for n in nums if n not in log_text)

WELL_KNOWN = {
    22: "SSH (remote login)",
    53: "DNS",
    80: "HTTP web traffic",
    443: "HTTPS web traffic",
    502: "Modbus/TCP (industrial control)",
    1883: "MQTT, the standard IoT messaging protocol",
}


def port_notes(row):
    notes = []
    for label, col in (("source", "tcp.srcport"), ("destination", "tcp.dstport")):
        p = valid_port(row[col])
        if p is None:
            continue
        if p in WELL_KNOWN:
            notes.append(f"{label} port {p} is {WELL_KNOWN[p]}")
        elif p >= 32768:
            notes.append(
                f"{label} port {p} is a temporary client port, "
                "normal for the client side of a connection"
            )
    return notes

def build_prompt(text, top3, votes, examples, knowledge, use_examples=False,
                 port_facts=(), describe_only=False):
    cand = "\n".join(f"- {c}: {p:.0%}" for c, p in top3)
    descs = [d for d, m in knowledge if m["kind"] == "description"]
    kn = "\n".join(f"- {d}" for d in descs) if descs else "- (none: classified as normal)"
    facts = "\n".join(f"- {n}" for n in port_facts) or "- (none)"
    ex_block = ""
    if use_examples:
        ex = "\n".join(f"- {d}" for d in examples)
        ex_block = f"SIMILAR PAST LOGS (reference only, NOT part of the current log):\n{ex}\n\n"
    bg_block = "" if describe_only else f"BACKGROUND ON THE ATTACK:\n{kn}\n\n"
    extra = ""
    if describe_only:
        extra = (
            "- This packet carries no payload or protocol content. Describe only what it "
            "shows (addresses, ports, flags). Do not say it is consistent with, or evidence of, any attack.\n"
        )
    return f"""You are a security analyst assistant for an IoT network.
A classifier has analysed one network log record. Explain the finding.

LOG RECORD (this is a single packet):
{text}

PORT FACTS (computed from the packet, reliable):
{facts}

CLASSIFIER DIAGNOSIS (top candidates):
{cand}

{ex_block}{bg_block}RULES:
- Treat the top candidate as the diagnosis. Do not change it.
- Write 2 to 3 sentences using only facts visible in the log record: addresses, ports, flags, payload text.
- Use the PORT FACTS to interpret ports. Never call a port non-standard or suspicious unless the facts say so.
- If the log has payload text, quote a short piece of it as evidence.
- Do not describe sizes as large or small.
- Say only what this single packet shows. Never describe other packets, repetition or patterns across packets.
- Do not use the classifier's probability as evidence.
- Do not list mitigations.
{extra}Reply with JSON only, in this form: {SCHEMA}"""


FLAG_MEANING = {
    "SYN": "starts a connection",
    "FIN": "closes a connection",
    "RST": "resets a connection",
    "PSH": "pushes data to the application",
    "ACK": "acknowledges received data",
}


def template_explanation(row, predicted, text):
    bits = [text]
    flags = decode_flags(row["tcp.flags"])
    if flags:
        meanings = [FLAG_MEANING[f] for f in flags.split(",") if f in FLAG_MEANING]
        bits.append(f"The flags ({flags}) mean: {'; '.join(meanings)}.")
    bits.extend(n[0].upper() + n[1:] + "." for n in port_notes(row))
    bits.append(
        "This packet has no payload or protocol content, so on its own it does not "
        f"show an attack. The classifier labelled it {predicted}."
    )
    return " ".join(bits)

def analyse(row, use_examples=False):
    text = row_to_text(row)
    top3 = classify(row)
    predicted, top_prob = top3[0]
    votes, examples = retrieve_examples(text, predicted)
    knowledge = [] if predicted == "Normal" else retrieve_knowledge(text, predicted)
    no_evidence = not any(w in text for w in EVIDENCE_WORDS)
    weak_evidence = no_evidence and predicted not in HEADER_ONLY_OK
    if no_evidence:
        explanation = template_explanation(row, predicted, text)
    else:
        prompt = build_prompt(text, top3, votes, examples, knowledge, use_examples,
                              port_notes(row))
        raw = generate(prompt, json_mode=True)
        try:
            explanation = json.loads(raw).get("explanation", "")
        except (json.JSONDecodeError, AttributeError):
            explanation = ""

    support = votes.count(predicted)
    bad_numbers = ungrounded_numbers(explanation, text)
    notes = []
    if support < 3:
        notes.append(f"only {support} of {len(votes)} nearest labelled logs agree")
    if top_prob < 0.7:
        notes.append(f"classifier confidence is only {top_prob:.0%}")
    if weak_evidence:
        notes.append(
            "this packet shows no payload or protocol content, so the diagnosis "
            "rests on patterns the classifier learned, not on visible evidence"
        )
    if bad_numbers:
        notes.append(
            "the explanation mentions numbers that are not in the log ("
            + ", ".join(bad_numbers) + "), so treat it with caution"
        )

    mitigations = [
        {"text": d, "source": m["source"], "capec_id": m["capec_id"]}
        for d, m in knowledge
        if m["kind"] == "mitigation"
    ][:3]

    return {
        "log_text": text,
        "top3": top3,
        "attack_type": predicted,
        "capec_id": knowledge[0][1]["capec_id"] if knowledge else None,
        "retrieval_support": f"{support} of {len(votes)} nearest labelled logs were {predicted}",
        "explanation": explanation,
        "used_llm": not no_evidence,
        "ungrounded_numbers": bad_numbers,
        "mitigations": mitigations,
        "uncertainty": "; ".join(notes) if notes else "none",
    }

if __name__ == "__main__":
    test = pd.read_csv("data/test.csv", low_memory=False)
    for cls in ("DDoS_TCP", "Password", "Normal"):
        row = test[test["Attack_type"] == cls].sample(1, random_state=5).iloc[0]
        start = time.time()
        out = analyse(row)
        print("=" * 70)
        print("TRUE LABEL:", cls)
        print("LOG:", out["log_text"][:200])
        print(json.dumps({k: v for k, v in out.items() if k != "log_text"}, indent=2))
        print(f"({time.time() - start:.1f} seconds)")


import json

import chromadb
from sentence_transformers import SentenceTransformer

with open("data/capec.json", encoding="utf-8") as f:
    kb = json.load(f)

docs, metas, ids = [], [], []
for entry in kb:
    cls = entry["attack_type"]
    base = {
        "attack_type": cls,
        "capec_id": entry["capec_id"],
        "mapping": entry["mapping"],
    }
    docs.append(f'{entry["capec_name"]} ({entry["capec_id"]}). {entry["description"]}')
    metas.append({**base, "kind": "description", "source": "capec"})
    ids.append(f"{cls}-desc")
    for i, m in enumerate(entry["mitigations"]):
        docs.append(m["text"])
        metas.append({**base, "kind": "mitigation", "source": m["source"]})
        ids.append(f"{cls}-mit{i}")

model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(docs, batch_size=32)

client = chromadb.PersistentClient(path="chroma_db")
try:
    client.delete_collection("mitigations")
except Exception:
    pass
collection = client.create_collection("mitigations")
collection.add(ids=ids, embeddings=embeddings.tolist(), documents=docs, metadatas=metas)
print("Classes:", len(kb), "| Stored", collection.count(), "knowledge chunks")

tests = [
    ("stop a flood of SYN packets", "DDoS_TCP"),
    ("prevent injected database queries", "SQL_injection"),
    ("protect against password guessing", "Password"),
]
for question, cls in tests:
    q = model.encode([question]).tolist()
    res = collection.query(query_embeddings=q, n_results=2, where={"attack_type": cls})
    print("\nQ:", question, "| class:", cls)
    for d in res["documents"][0]:
        print("  -", d[:110])

q = model.encode(["how do I defend against too many TCP connection requests"]).tolist()
res = collection.query(query_embeddings=q, n_results=3)
print("\nUnfiltered top 3 classes:", [m["attack_type"] for m in res["metadatas"][0]])

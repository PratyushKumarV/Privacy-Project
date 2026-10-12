import chromadb
import joblib
import pandas as pd
import os
from collections import Counter
from sentence_transformers import SentenceTransformer

from describe import row_to_text
from train_classifier import make_features

K = 5
PER_CLASS = 200

test = pd.read_csv("data/test.csv", low_memory=False)
parts = [
    g.sample(min(len(g), PER_CLASS), random_state=7)
    for _, g in test.groupby("Attack_type")
]
sub = pd.concat(parts).reset_index(drop=True)

model = SentenceTransformer("all-MiniLM-L6-v2")
texts = sub.apply(row_to_text, axis=1).tolist()
emb = model.encode(texts, batch_size=64, show_progress_bar=True)

collection = chromadb.PersistentClient(path="chroma_db").get_collection("examples")
neighbours = []
for start in range(0, len(emb), 500):
    res = collection.query(query_embeddings=emb[start:start + 500].tolist(), n_results=K)
    neighbours += [[m["attack_type"] for m in row] for row in res["metadatas"]]

true = sub["Attack_type"].tolist()
bundle = joblib.load("models/clf_robust.joblib")
clf_pred = bundle["model"].predict(make_features(sub)[bundle["columns"]]).tolist()

result = pd.DataFrame({
    "true": true,
    "retrieval_top1": [n[0] == t for n, t in zip(neighbours, true)],
    "retrieval_vote": [Counter(n).most_common(1)[0][0] == t for n, t in zip(neighbours, true)],
    "precision_at_5": [sum(x == t for x in n) / K for n, t in zip(neighbours, true)],
    "classifier": [p == t for p, t in zip(clf_pred, true)],
})

print(result.groupby("true").mean().round(3).to_string())
print()
print("OVERALL (equal weight per class):")
print(result.drop(columns="true").mean().round(3).to_string())
os.makedirs("outputs", exist_ok=True)
result.groupby("true").mean().round(3).to_csv("outputs/retrieval_results.csv")

votes = [Counter(n).most_common(1)[0][0] for n in neighbours]
agree = [v == p for v, p in zip(votes, clf_pred)]
check = pd.DataFrame({"agree": agree, "classifier_right": result["classifier"]})
print()
print("Classifier accuracy when it agrees / disagrees with the retrieval vote:")
print(check.groupby("agree")["classifier_right"].agg(["mean", "count"]).round(3))

hard = ["Password", "Uploading", "DDoS_HTTP", "SQL_injection", "XSS", "Port_Scanning"]
mask = result["true"].isin(hard)
print()
print("Same check, hard classes only:")
print(check[mask].groupby("agree")["classifier_right"].agg(["mean", "count"]).round(3))
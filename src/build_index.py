import chromadb
import pandas as pd
from sentence_transformers import SentenceTransformer

from describe import row_to_text

N_PER_CLASS = 300

train = pd.read_csv("data/train.csv", low_memory=False)

parts = [
    g.sample(min(len(g), N_PER_CLASS), random_state=42)
    for _, g in train.groupby("Attack_type")
]
index_df = pd.concat(parts).reset_index(drop=True)
index_df["text"] = index_df.apply(row_to_text, axis=1)

model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(index_df["text"].tolist(), batch_size=64, show_progress_bar=True)

client = chromadb.PersistentClient(path="chroma_db")
try:
    client.delete_collection("examples")
except Exception:
    pass
collection = client.create_collection("examples")

collection.add(
    ids=[str(i) for i in index_df.index],
    embeddings=embeddings.tolist(),
    documents=index_df["text"].tolist(),
    metadatas=[{"attack_type": t} for t in index_df["Attack_type"]],
)
print("Stored", collection.count(), "examples")

test = pd.read_csv("data/test.csv", low_memory=False).sample(8, random_state=1)
for _, row in test.iterrows():
    q = model.encode([row_to_text(row)]).tolist()
    res = collection.query(query_embeddings=q, n_results=5)
    print("True:", row["Attack_type"], "| Retrieved:", [m["attack_type"] for m in res["metadatas"][0]])
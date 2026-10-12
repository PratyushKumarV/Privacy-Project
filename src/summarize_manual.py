import pandas as pd

df = pd.read_csv("outputs/pipeline_results.csv")
llm = df[df["used_llm"]]

for col in ("manual_no_examples", "manual_with_examples"):
    print(col)
    marks = llm[col].fillna("(blank)").astype(str).str.strip().str.lower()
    print(marks.value_counts().to_string())
    print()

print("LLM rows:", len(llm), "| code-written rows:", int((~df["used_llm"]).sum()))
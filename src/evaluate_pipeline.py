import os
import time

import pandas as pd

from pipeline import analyse

PER_CLASS = 2

test = pd.read_csv("data/test.csv", low_memory=False)
parts = [
    g.sample(min(len(g), PER_CLASS), random_state=11)
    for _, g in test.groupby("Attack_type")
]
sample = pd.concat(parts).reset_index(drop=True)

os.makedirs("outputs", exist_ok=True)
rows = []
start = time.time()
for i, (_, row) in enumerate(sample.iterrows(), 1):
    plain = analyse(row, use_examples=False)
    with_ex = analyse(row, use_examples=True)
    rows.append({
        "true_label": row["Attack_type"],
        "predicted": plain["attack_type"],
        "label_correct": plain["attack_type"] == row["Attack_type"],
        "top_probability": round(plain["top3"][0][1], 3),
        "retrieval_support": plain["retrieval_support"],
        "used_llm": plain["used_llm"],
        "uncertainty_flagged": plain["uncertainty"] != "none",
        "uncertainty": plain["uncertainty"],
        "log": plain["log_text"],
        "explanation_no_examples": plain["explanation"],
        "invented_numbers_no_examples": len(plain["ungrounded_numbers"]),
        "explanation_with_examples": with_ex["explanation"],
        "invented_numbers_with_examples": len(with_ex["ungrounded_numbers"]),
        "manual_no_examples": "",
        "manual_with_examples": "",
        "manual_notes": "",
    })
    pd.DataFrame(rows).to_csv("outputs/pipeline_results.csv", index=False, encoding="utf-8-sig")
    print(f"{i}/{len(sample)} done ({time.time() - start:.0f}s elapsed)")

res = pd.DataFrame(rows)
llm = res[res["used_llm"]]
wrong = res[~res["label_correct"]]
print()
print("Rows:", len(res), "| labels correct:", int(res["label_correct"].sum()))
print("Wrong labels:", len(wrong), "| of which carry an uncertainty note:", int(wrong["uncertainty_flagged"].sum()))
print("Correct labels carrying an uncertainty note:", int((res["label_correct"] & res["uncertainty_flagged"]).sum()))
print("Rows explained by the LLM (not the template):", len(llm))
print("Invented numbers on LLM rows, without examples:", int(llm["invented_numbers_no_examples"].sum()))
print("Invented numbers on LLM rows, with examples:   ", int(llm["invented_numbers_with_examples"].sum()))
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, "src")
from describe import row_to_text  # noqa: E402
from pipeline import analyse  # noqa: E402

st.set_page_config(page_title="IoT Log Analyst", layout="wide")
st.title("IoT security log analyst")
st.caption(
    "Classifier + similarity search + CAPEC knowledge base + local LLM. "
    "Demo on held-out Edge-IIoTset test rows."
)


@st.cache_data
def load_test():
    return pd.read_csv("data/test.csv", low_memory=False)


test = load_test()

st.sidebar.header("Choose a log")
choice = st.sidebar.selectbox("Sample from", ["(any)"] + sorted(test["Attack_type"].unique()))
if "seed" not in st.session_state:
    st.session_state.seed = 0
if st.sidebar.button("Draw a different log"):
    st.session_state.seed += 1
use_examples = st.sidebar.checkbox("Show similar past logs to the LLM", value=False)

pool = test if choice == "(any)" else test[test["Attack_type"] == choice]
row = pool.sample(1, random_state=st.session_state.seed).iloc[0]

st.subheader("Log record")
st.code(row_to_text(row), language=None)

if st.button("Analyse this log", type="primary"):
    with st.spinner("Analysing (the local LLM can take up to a minute)..."):
        out = analyse(row, use_examples=use_examples)

    left, right = st.columns(2)
    with left:
        st.subheader("Diagnosis")
        st.metric("Predicted attack", out["attack_type"])
        st.write("Framework reference:", out["capec_id"] or "none (normal traffic)")
        st.write("Retrieval support:", out["retrieval_support"])
        top3 = pd.DataFrame(out["top3"], columns=["class", "probability"]).set_index("class")
        st.bar_chart(top3)
    with right:
        st.subheader("Confidence notes")
        if out["uncertainty"] == "none":
            st.success("No warnings raised.")
        else:
            st.warning(out["uncertainty"])
        st.subheader("Explanation")
        st.write(out["explanation"] or "(no explanation produced)")
        st.caption(
            "Written by the local LLM." if out["used_llm"]
            else "Written by code from the packet fields (no payload or protocol content)."
        )

    st.subheader("Suggested mitigations")
    if out["mitigations"]:
        for m in out["mitigations"]:
            st.markdown(f"- {m['text']}  \n  *{m['capec_id']} | source: {m['source']}*")
        st.caption("source: capec = from the CAPEC entry, attack = from MITRE ATT&CK, "
                   "general = standard hardening advice added by the project authors.")
    else:
        st.info("No mitigations: this traffic was classified as normal.")

    with st.expander("Reveal the true label (demo only)"):
        st.write(row["Attack_type"])
# LLM + RAG Assistant for IoT Security Log Analysis

A hybrid system that reads one IoT/IIoT network log record and returns:

- a **diagnosis** (which of 14 attack types, or Normal), from a Random Forest classifier;
- a **second opinion** from similarity search over labelled example logs (RAG retrieval);
- a **reference and mitigations** from a small knowledge base built on MITRE CAPEC / ATT&CK;
- an **explanation** of the log, written by code when the packet has no content to read, and by a local LLM (Ollama, `mistral:latest`) when it does;
- **confidence notes** computed by code (not by the LLM) that say when the diagnosis should be treated with care.

Everything runs locally on Windows. No log data leaves the machine.

> **What this is and is not.** It is a working course project that measures its own weak spots honestly. It is not a deployable intrusion detector. The data are single packets from a lab testbed, and Section 9 lists the caveats you should state when presenting it.

---

## Table of contents

1. [Results at a glance](#1-results-at-a-glance)
2. [How the system works](#2-how-the-system-works)
3. [Project structure](#3-project-structure)
4. [Setup on Windows](#4-setup-on-windows)
5. [Build everything from scratch](#5-build-everything-from-scratch)
6. [Using the web app](#6-using-the-web-app)
7. [File-by-file reference](#7-file-by-file-reference)
8. [Data and knowledge base notes](#8-data-and-knowledge-base-notes)
9. [Findings, evaluation and limitations](#9-findings-evaluation-and-limitations)
10. [Troubleshooting](#10-troubleshooting)
11. [References](#11-references)

---

## 1. Results at a glance

All numbers below are from this project's own runs on **held-out test rows** (a stratified 20% split made before anything was trained or indexed).

| Question | Result |
|---|---|
| Classifier accuracy, all features | 94.2% (macro F1 0.894). Treat as an upper bound. |
| Classifier accuracy, **without** four session-like columns (`tcp.seq`, `tcp.ack`, `tcp.ack_raw`, `tcp.checksum`) | **86.3%** (macro F1 **0.812**). This is the version the system uses. |
| Pure retrieval as a classifier (vote of the 5 nearest labelled logs) vs the robust classifier, equal weight per class, 200 test rows per class | 84.7% vs 85.0%. A tie. |
| Classifier accuracy when classifier and retrieval vote **agree** / **disagree** | 91.7% (2,594 rows) / 42.4% (406 rows) |
| Same check, hard web-attack classes only | 79.6% (849 rows) / 43.6% (351 rows) |
| Explanations written by the LLM | Not formally scored. Informal inspection of sample outputs found wrong or overstated claims (Section 9.5). |

**The honest summary:** retrieval and the classifier are equally accurate here, so the hybrid is justified by what it adds (explanation, CAPEC mitigations, and a measured disagreement signal), not by higher accuracy. The weakest component is the LLM-written free text, which is why code writes the explanation whenever a packet has no payload or protocol content.

---

## 2. How the system works

```
 one log row (63 columns)
        |
        +--> row_to_text()  ->  plain-English description of the packet
        |
        +--> classifier (Random Forest, numeric features) -> top 3 classes + probabilities
        |
        +--> embed description (all-MiniLM-L6-v2) -> ChromaDB "examples"
        |         -> 5 nearest labelled logs -> vote (second opinion)
        |         -> 3 nearest logs of the predicted class (optional LLM context)
        |
        +--> ChromaDB "mitigations" (filtered to the predicted class)
        |         -> CAPEC description + up to 3 mitigations, each tagged with its source
        |
        +--> has payload / protocol content?
                 no  -> explanation written by code from the packet fields
                 yes -> prompt Mistral (via Ollama) for a 2-3 sentence explanation
        |
        v
 label + framework ID + retrieval support + explanation + mitigations + confidence notes
```

### Who produces what

| Output | Produced by | Can it be wrong? |
|---|---|---|
| Attack label | Random Forest | Yes (see accuracy above) |
| CAPEC / ATT&CK ID | Copied from the knowledge base | Only if the mapping is weak (Section 8.2) |
| Mitigations | Copied from the knowledge base, with a `source` tag | Same |
| "Retrieval support" (e.g. "4 of 5 nearest logs were X") | Counted by code | No |
| Confidence notes | Rules in code | No |
| Explanation, packets with no content | Code (template) | Describes only what the packet shows |
| Explanation, packets with content | Mistral | **Yes** |

The design rule: **compute in code whatever code can know**, and give the LLM only the one job it is needed for.

### Confidence notes (raised in code)

A note is shown when any of these is true:

- fewer than 3 of the 5 nearest labelled logs agree with the classifier;
- the classifier's top probability is below 70%;
- the packet has no payload or protocol content **and** the predicted class is one that needs visible content (the web-attack classes);
- the LLM's explanation mentions a number that does not appear in the log.

---

## 3. Project structure

```
Privacy and Security Project/
|-- app.py                      Streamlit web app (run from this folder)
|-- README.md
|-- .streamlit/config.toml      Quiets Streamlit's file watcher (see Section 10)
|-- .venv/                      Python virtual environment
|-- data/
|   |-- ML-EdgeIIoT-dataset.csv     Original dataset (157,800 rows x 63 columns)
|   |-- train.csv, test.csv         80/20 stratified split
|   `-- capec.json                  Knowledge base source (14 attack classes)
|-- models/
|   |-- clf.joblib                  Classifier, all features (upper bound only)
|   `-- clf_robust.joblib           Classifier used by the system
|-- chroma_db/                  Vector database ("examples", "mitigations")
|-- outputs/
|   |-- retrieval_results.csv       Per-class retrieval results (optional)
|   `-- pipeline_results.csv        30-row pipeline evaluation sheet
`-- src/
    |-- inspect_data.py         Shape, columns, class counts
    |-- split_data.py           Stratified train/test split
    |-- textify.py              Helpers: clean, num, decode_flags, decode_payload
    |-- describe.py             row_to_text() and its IP/port validators
    |-- train_classifier.py     Feature builder + Random Forest (all features)
    |-- robustness.py           Retrain without session-like columns; saves clf_robust
    |-- build_index.py          Embeds 4,500 example descriptions into ChromaDB
    |-- build_kb.py             Embeds the CAPEC knowledge base into ChromaDB
    |-- llm.py                  generate(prompt) -> Ollama
    |-- pipeline.py             analyse(row): the whole system
    |-- evaluate_retrieval.py   Retrieval vs classifier vs agreement signal
    `-- evaluate_pipeline.py    Optional: runs 30 test rows through the pipeline, prints automatic counts
```

---

## 4. Setup on Windows

### 4.1 Python and the virtual environment

Install Python 3.11 or newer from python.org and tick **Add python.exe to PATH**. (This project was run on Python 3.13.)

```powershell
cd "D:\MS Visual Studio Code\Projects\Privacy and Security Project"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Your prompt should start with `(.venv)`. If PowerShell blocks the script:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 4.2 Libraries

```powershell
python -m pip install --upgrade pip
pip install pandas numpy scikit-learn sentence-transformers chromadb streamlit requests joblib rouge-score tqdm
```

You do **not** need `torchvision`. Streamlit may print many `torchvision` errors; they are harmless (Section 10).

### 4.3 Ollama and the model

1. Install Ollama from ollama.com. It runs a local server on port 11434.
2. Check you have the model:
   ```powershell
   ollama list
   ```
   `mistral:latest` must appear. If not: `ollama pull mistral`.
3. On a 4 GB GPU, Mistral does not fit fully and runs split between CPU and GPU (check with `ollama ps`). It works but takes roughly 15 to 30 seconds per LLM-written explanation. Closing GPU-heavy apps (browsers, animated wallpapers) before running helps.

### 4.4 The dataset

Download **Edge-IIoTset** from Kaggle (Ferrag et al.). The package is about 10 GB, but you only need one file: `ML-EdgeIIoT-dataset.csv`. Put it in `data\`. The rest (raw packet captures) can be deleted.

---

## 5. Build everything from scratch

Run these from the project folder with `(.venv)` active. The first run of anything that uses the embedding model downloads about 90 MB, so it needs internet once.

| # | Command | What it does | Expected result |
|---|---|---|---|
| 1 | `python src\inspect_data.py` | Looks at the dataset | Shape `(157800, 63)`, 15 classes |
| 2 | `python src\split_data.py` | 80/20 stratified split | `Train: 126240 Test: 31560` |
| 3 | `python src\train_classifier.py` | Trains on all features (upper bound), saves `models\clf.joblib` | Accuracy about 0.942 |
| 4 | `python src\robustness.py` | Retrains without 4 session-like columns, saves `models\clf_robust.joblib` | Accuracy about 0.863 |
| 5 | `python src\build_index.py` | Builds the example index | `Stored 4500 examples` |
| 6 | `python src\build_kb.py` | Builds the knowledge base | `Classes: 14 | Stored 63 knowledge chunks` |
| 7 | `python src\llm.py` | Tests the Ollama connection | A sentence, then valid JSON |
| 8 | `python src\pipeline.py` | Runs 3 demo rows end to end | Three structured results |
| 9 | `python src\evaluate_retrieval.py` | Retrieval vs classifier table | Overall 0.847 vs 0.850 |
| 10 | `python src\evaluate_pipeline.py` | Optional: 30 test rows through the full pipeline | Writes `outputs\pipeline_results.csv` and prints automatic counts |

Steps 1 to 6 are the build. Step 7 onward are tests and evaluation. Steps 7, 8 and 10 need Ollama running. Step 9 does not use the LLM, so it works without Ollama.

---

## 6. Using the web app

The app is a demo front end for `pipeline.analyse()`. It analyses **sample rows from the held-out test set**. It does not accept pasted or uploaded logs.

### 6.1 Start it

1. **Start Ollama.** Open Ollama from the Start menu (a llama icon appears in the system tray). Confirm by opening `http://localhost:11434` in a browser, which should say "Ollama is running".
2. **Open PowerShell in the project folder** and activate the environment:
   ```powershell
   cd "D:\MS Visual Studio Code\Projects\Privacy and Security Project"
   .\.venv\Scripts\Activate.ps1
   ```
3. **Run the app** from the project root, the folder that contains `app.py`:
   ```powershell
   streamlit run app.py
   ```
4. Wait for the line `Local URL: http://localhost:8501`. A browser tab normally opens by itself. If not, open that address.
5. **Stop the app** later with **Ctrl+C** in the PowerShell window.

If port 8501 is busy: `streamlit run app.py --server.port 8502`.

### 6.2 The screen

**Sidebar (left)**

- **Sample from:** choose a traffic type (for example `Password`, `DDoS_TCP`, `Normal`) or `(any)`. The app draws a random test row of that type.
- **Draw a different log:** picks another random row for the current choice.
- **Show similar past logs to the LLM:** off by default. In our small comparison it gave no benefit and may add errors, so leave it off unless you are experimenting.

**Main page**

- **Log record:** the packet described in plain English (addresses, ports, flags, payload text if any). This is what the system actually reads.
- **Analyse this log:** runs the whole pipeline.

### 6.3 Reading the result

| Panel | What it shows | How to read it |
|---|---|---|
| **Predicted attack** | The classifier's label | The diagnosis. It can be wrong. |
| **Framework reference** | CAPEC or ATT&CK ID, or "none" for normal traffic | Some are only the closest match (Section 8.2). |
| **Retrieval support** | e.g. "5 of 5 nearest labelled logs were DDoS_TCP" | A second, independent opinion. 5 of 5 is strong. 2 of 5 is weak. |
| **Bar chart** | Top 3 classes with probabilities | A probability near 100% does **not** prove the packet shows an attack (Section 9.4). |
| **Confidence notes** | Green "No warnings", or a yellow list of reasons for caution | Take warnings seriously. When classifier and retrieval disagree, the classifier was right only about 42% of the time in testing. |
| **Explanation** | A short account of the packet | The caption says who wrote it: **code** (packet has no payload or protocol content) or **the local LLM**. Read LLM-written text critically. |
| **Suggested mitigations** | Up to 3 actions with CAPEC ID and a source tag | `capec` = from the CAPEC entry. `attack` = from MITRE ATT&CK. `general` = standard hardening advice added by the project authors, not quoted from MITRE. |
| **Reveal the true label** | The real answer from the dataset | For demos: show the prediction first, then reveal. |

### 6.4 Timing

- Packets with no payload or protocol content: **well under a second** (code writes the explanation).
- Packets with payload, HTTP or MQTT content: about **15 to 30 seconds** (Mistral on a split CPU/GPU). The first LLM call after starting Ollama is the slowest.

### 6.5 A good demo sequence

1. Choose **Password**, analyse. Instant. Note the warning that the packet shows no content, and the weak retrieval support. This shows the system flagging its own uncertainty.
2. Choose **DDoS_TCP**, analyse. The LLM reads the payload text (a run of `X` characters). Strong retrieval support, no warnings.
3. Choose **Normal**, analyse. No mitigations, because nothing needs mitigating.
4. Open **Reveal the true label** after each, and discuss agreement.

---

## 7. File-by-file reference

### `src/textify.py` (helpers)
- `clean(v)`: returns `None` for empty-looking values (`""`, `0`, `0.0`, `nan`), otherwise the trimmed text. Most dataset columns are 0 for any given packet.
- `num(v)`: safe number conversion. Text or NaN becomes 0.0 instead of crashing.
- `decode_flags(v)`: turns the TCP flags number into names using bit tests. `24` becomes `PSH,ACK`.
- `decode_payload(v)`: the payload column is hex text. This decodes it to readable text, and returns `None` if less than 80% of the bytes are printable (binary junk is dropped).

### `src/describe.py` (packet to text)
- `valid_ip`, `valid_port`, `is_external`: validation helpers. This dataset has some misaligned rows (for example an IP address sitting in `frame.time`, or a service name in a port column), so values are validated, not trusted.
- `row_to_text(row)`: builds one description per packet. It infers the protocol (ICMP, ARP, UDP, TCP) from which fields are filled, then adds HTTP, MQTT, service-name and payload sentences if present. It never reads the label columns.

### `src/train_classifier.py`
- `make_features(df)`: converts the table to purely numeric features. Text columns become two numbers each (present, length). `Attack_label` and `Attack_type` are never features. IPs are excluded by default.
- Trains a 100-tree Random Forest with `class_weight="balanced"`, reports accuracy with and without exact-duplicate test rows, and saves `models\clf.joblib`.

### `src/robustness.py`
Retrains without `tcp.seq`, `tcp.ack`, `tcp.ack_raw`, `tcp.checksum` and saves `models\clf_robust.joblib`. This is the model used by the pipeline.

### `src/build_index.py`
Takes 300 random training rows per class (4,500 total), describes them with `row_to_text`, embeds them with all-MiniLM-L6-v2, and stores them in the ChromaDB collection `examples` with the true class as metadata. Only training rows are indexed, so no test row can be retrieved as its own neighbour.

### `src/build_kb.py` and `data/capec.json`
Each of the 14 attack classes has one description chunk and several mitigation chunks. Every mitigation carries a `source` tag (`capec`, `attack`, `general`). They are embedded into the collection `mitigations`, filterable by `attack_type`.

### `src/llm.py`
`generate(prompt, model="mistral:latest", json_mode=False, temperature=0.1)` posts to Ollama's local API and returns the text. Low temperature keeps results nearly repeatable.

### `src/pipeline.py`
- `classify(row)`: top 3 classes with probabilities.
- `retrieve_examples(text, predicted)`: the 5-neighbour vote, plus 3 nearest logs of the predicted class.
- `retrieve_knowledge(text, predicted)`: knowledge-base chunks for the predicted class.
- `port_notes(row)`: plain-English facts about the ports (for example "1883 is MQTT", "54904 is a temporary client port") given to the LLM so it does not guess.
- `build_prompt(...)`: assembles the prompt. The LLM may only write the explanation; rules tell it to use only facts in the log.
- `template_explanation(...)`: the code-written explanation for packets with no content.
- `ungrounded_numbers(...)`: a cheap check that flags numbers in an explanation that are not in the log.
- `analyse(row, use_examples=False)`: runs everything and returns one dictionary.

### `app.py`
Streamlit front end (Section 6).

### Evaluation scripts
- `evaluate_retrieval.py`: top-1 accuracy, vote accuracy, Precision@5 and the classifier on the same 3,000 rows, plus the agreement analysis.
- `evaluate_pipeline.py`: optional. Runs 2 test rows per class (30 rows) through `analyse`, with and without examples in the prompt, and prints automatic counts (labels correct, warnings raised, invented numbers). It also writes `outputs\pipeline_results.csv`; the empty `manual_*` columns in that file are unused.

---

## 8. Data and knowledge base notes

### 8.1 The dataset

Edge-IIoTset: 157,800 rows after processing, 63 columns, 15 labels. Classes are very uneven (Normal 24,301 rows, Fingerprinting 1,001), which is why evaluation samples equal numbers per class. Most columns are zero for any packet, some columns are shifted in some rows, and the IPs are a fixed lab testbed.

### 8.2 CAPEC / ATT&CK mapping quality

Each entry in `capec.json` has a `mapping` field. Be upfront about the weak ones.

| Attack class | Reference | Mapping |
|---|---|---|
| DDoS_HTTP | CAPEC-488 HTTP Flood | exact |
| DDoS_ICMP | CAPEC-487 ICMP Flood | exact |
| DDoS_TCP | CAPEC-482 TCP Flood | exact |
| DDoS_UDP | CAPEC-486 UDP Flood | exact |
| Fingerprinting | CAPEC-224 Fingerprinting | exact |
| MITM | CAPEC-94 Adversary in the Middle | exact (mitigations from ATT&CK T0830) |
| Password | CAPEC-49 Password Brute Forcing | exact |
| Port_Scanning | CAPEC-300 Port Scanning | exact |
| SQL_injection | CAPEC-66 SQL Injection | exact |
| Vulnerability_scanner | CAPEC-310 Scanning for Vulnerable Software | exact |
| XSS | CAPEC-63 Cross-Site Scripting | exact |
| Uploading | CAPEC-650 Upload a Web Shell | **closest** (no generic malicious-upload pattern) |
| Backdoor | CAPEC-523 Malicious Software Implanted | **closest** (supply-chain framing) |
| Ransomware | ATT&CK T1486 Data Encrypted for Impact | **none in CAPEC** |

Mitigation sources: text tagged `capec` or `attack` is paraphrased from the framework entry. Text tagged `general` is standard hardening advice written for this project, and several classes (ICMP flood, UDP flood, Fingerprinting, Port scanning, Vulnerability scanner) rely mostly on it. IDs and names were checked against MITRE; not every sentence was.

---

## 9. Findings, evaluation and limitations

### 9.1 Evaluation design
- The split is stratified, done before any training or indexing, and fixed with `random_state=42`.
- The classifier trains on all training rows. The retrieval index uses 300 training rows per class. Test rows never enter either.
- Retrieval and the classifier are compared on the **same** 3,000 test rows (200 per class).

### 9.2 The leakage finding
Removing four session-like columns dropped accuracy from 94.2% to 86.3%, mostly in the web-attack classes:

| Class | F1 with all columns | F1 without |
|---|---|---|
| Password | 0.866 | 0.553 |
| Uploading | 0.916 | 0.698 |
| XSS | 0.888 | 0.659 |
| SQL_injection | 0.884 | 0.722 |
| DDoS_HTTP | 0.845 | 0.712 |

This fits the explanation that the full model partly recognised sessions it had seen in training. It does not prove it, since those columns also carry some legitimate signal. Even 86.3% may be optimistic: the split is by packet, and the dataset has no session IDs, so a session-level split was impossible. Retrieval descriptions also contain ephemeral port numbers, which may carry the same leak in text form (not tested).

### 9.3 Retrieval vs classifier
A text-similarity search over described packets matches the Random Forest (84.7% vs 85.0%) once the leaky columns are removed. Both fail in the same place: Password, Uploading, DDoS_HTTP, SQL_injection and XSS all sit between about 0.5 and 0.8, because single packets of these attacks look alike.

### 9.4 The agreement signal
Disagreement between the classifier and retrieval is a usable warning: the classifier was right 91.7% of the time when they agreed and 42.4% when they disagreed (79.6% vs 43.6% within the hard classes). In the hard classes this flags about 3 packets in 10 and contains roughly half of the classifier's errors, but 44% of the flagged packets were actually correct. The test set is balanced, so real-traffic rates would differ.

The classifier's probability is **not** a good measure of evidence. A lone `FIN,ACK` packet that tells a human nothing can still get a 96% to 100% probability, which is why the "no visible evidence" note exists.

### 9.5 Explanation quality
The explanation text was **not formally scored**. Only automatic checks exist: the number check (any number in an explanation that is not in the log is flagged), the 30-row run's counts, and the confidence notes. These catch invented numbers, not wrong reasoning.

Informal reading of sample outputs, before the code-written explanations were added, showed these recurring problems with LLM-written text:

1. A correct description followed by attack language one packet cannot support ("high rate", "floods the server", "many paths").
2. Mixing up which side of a connection is the client and which is the server.
3. Treating dataset artifacts, such as a missing IP header, as attack evidence.
4. Quoting prompt terms (such as "PORT FACTS") as if they were facts about the packet.
5. Retrieved past logs leaking into the account of the current packet (no benefit was seen from including them).

This is why packets with no payload or protocol content now get a code-written explanation. The explanation of packets that do carry content is still LLM-written and should be read critically. Present it as the least reliable output of the system.

### 9.6 Limitations to state when presenting
1. **Single-packet data.** Many attacks only show up across packets, which this dataset does not keep as sessions.
2. **Lab testbed.** Fixed IPs and tool signatures (for example `Hydra`, `TESTING_PURPOSES_ONLY`) make some classes easier than real traffic.
3. **Packet-level split.** Results are probably optimistic for the reason in 9.2.
4. **Balanced evaluation.** Real traffic is mostly Normal, so real false-alarm rates differ.
5. **Weak classes.** Password, Uploading, XSS, SQL_injection and DDoS_HTTP are weak for both methods. MITM is easy mainly because of a parsing artifact (missing IP header), not attack behaviour, and has many false alarms (precision about 0.40).
6. **LLM component.** A 7B model on a 4 GB GPU can still write wrong technical claims, the number check catches only one kind of error, and explanation quality was not formally measured.
7. **Knowledge base.** Three mappings are only approximate, and many mitigations are general advice.
8. **Demo scope.** The web app analyses test rows only. It is not connected to live traffic.

### 9.7 Possible next steps
Group packets into windows or sessions and describe counts (for example "40 SYN packets to 30 ports"); build a session-level split; test retrieval without port numbers; add numeric-aware representations; compare a second LLM.

---

## 10. Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `ConnectionRefusedError ... 11434` | Ollama server not running | Start Ollama from the Start menu or run `ollama serve`; check `http://localhost:11434` |
| `404` from `llm.py` | Model name not installed | `ollama list`; set `MODEL` in `llm.py` to a listed name (for example `mistral:latest`) |
| `ollama pull` fails with `TLS handshake timeout` | Network problem | Retry on another network (for example a phone hotspot); not needed if Mistral is installed |
| Mistral is slow, `ollama ps` shows `51%/49% CPU/GPU` | 4 GB GPU too small for a 7B model | Expected. Close GPU-heavy apps, or use a smaller model |
| `KeyError: 'Attack_type'` in an old sampling script | pandas 3.x `groupby().apply()` drops the group column | Use the loop-based sampling now in the project |
| `KeyError: 'used_llm'` | `pipeline.py` return dictionary missing `"used_llm": not no_evidence` | Add that line to the `return {...}` in `analyse` |
| Classifier numbers did not change after switching models | An evaluation script still loads `models\clf.joblib` | `Select-String -Path .\src\*.py -Pattern "clf"`; the pipeline and `evaluate_retrieval.py` should load `clf_robust.joblib` |
| Hundreds of `torchvision` errors when Streamlit starts | Streamlit's file watcher scans every `transformers` module | Harmless. Run `streamlit run app.py --server.fileWatcherType none`, or create `.streamlit\config.toml` with `[server]` and `fileWatcherType = "none"`. After that, press **R** in the browser (or restart) to see code edits |
| Streamlit page does not open | Port busy or app not started | Use `--server.port 8502`; read the first lines of the PowerShell output for the URL |
| `ModuleNotFoundError: pipeline` when running `app.py` | App not run from the project root | `cd` into the folder that contains `app.py` and `src\` first |
| `ChromaDB ... collection does not exist` | Indexes not built | Run `python src\build_index.py` and `python src\build_kb.py` |
| A Normal packet shows "Written by the local LLM" and takes 15 s | `pipeline.py` still uses the old condition for template explanations | In `analyse`, the explanation switch must be `if no_evidence:` where `no_evidence = not any(w in text for w in EVIDENCE_WORDS)`; the warning note must use `if weak_evidence:` |

---

## 11. References

- Ferrag, M. A. et al. *Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications.* IEEE Access, 2022. Dataset on Kaggle: "edgeiiotset-cyber-security-dataset-of-iot-iiot".
- MITRE CAPEC (Common Attack Pattern Enumeration and Classification), https://capec.mitre.org
- MITRE ATT&CK, https://attack.mitre.org
- Reimers, N., Gurevych, I. *Sentence-BERT.* The `all-MiniLM-L6-v2` embedding model, from the `sentence-transformers` library.
- ChromaDB, https://www.trychroma.com
- Ollama, https://ollama.com, and the Mistral 7B model.

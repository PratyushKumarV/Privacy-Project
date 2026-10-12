import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from textify import clean
from describe import valid_ip, is_external

TEXT_ONLY = [
    "http.file_data", "http.request.uri.query", "http.request.method",
    "http.referer", "http.request.full_uri", "http.request.version",
    "tcp.options", "tcp.payload", "dns.qry.name", "mqtt.msg", "mqtt.topic",
    "mqtt.protoname", "mqtt.conack.flags",
    "arp.dst.proto_ipv4", "arp.src.proto_ipv4",
]
SKIP = ["Attack_type", "Attack_label", "frame.time", "ip.src_host", "ip.dst_host"]


def make_features(df, use_ips=False):
    feats = pd.DataFrame(index=df.index)
    for c in df.columns:
        if c in SKIP:
            continue
        if c in TEXT_ONLY:
            feats[c + "__present"] = df[c].map(lambda v: 0 if clean(v) is None else 1)
            feats[c + "__len"] = df[c].map(lambda v: len(clean(v) or ""))
        else:
            feats[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    if use_ips:
        for name, col in (("src", "ip.src_host"), ("dst", "ip.dst_host")):
            ips = df[col].map(valid_ip)
            feats[name + "_last_octet"] = ips.map(
                lambda ip: int(ip.split(".")[-1]) if isinstance(ip, str) else -1
            )
            feats[name + "_external"] = ips.map(
                lambda ip: 1 if isinstance(ip, str) and is_external(ip) else 0
            )
    return feats


if __name__ == "__main__":
    train = pd.read_csv("data/train.csv", low_memory=False)
    test = pd.read_csv("data/test.csv", low_memory=False)
    y_train, y_test = train["Attack_type"], test["Attack_type"]

    for use_ips in (False, True):
        X_train = make_features(train, use_ips)
        X_test = make_features(test, use_ips)

        clf = RandomForestClassifier(
            n_estimators=100, n_jobs=-1, class_weight="balanced", random_state=42
        )
        clf.fit(X_train, y_train)
        pred = clf.predict(X_test)

        train_hashes = set(pd.util.hash_pandas_object(X_train, index=False))
        is_dup = pd.util.hash_pandas_object(X_test, index=False).isin(train_hashes)
        keep = ~is_dup.to_numpy()

        print("=" * 60)
        print("IP features used:", use_ips)
        print("Accuracy, all test rows:", round(accuracy_score(y_test, pred), 4))
        print("Test rows with an identical twin in train:", round(is_dup.mean(), 3))
        print("Accuracy, rows with NO twin:", round(accuracy_score(y_test[keep], pred[keep]), 4))

        if not use_ips:
            print(classification_report(y_test, pred, digits=3))
            os.makedirs("models", exist_ok=True)
            joblib.dump({"model": clf, "columns": list(X_train.columns)}, "models/clf.joblib")
            print("Saved models/clf.joblib")
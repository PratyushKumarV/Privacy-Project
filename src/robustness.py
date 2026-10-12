import pandas as pd
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score

from train_classifier import make_features

DROP = ["tcp.seq", "tcp.ack", "tcp.ack_raw", "tcp.checksum"]

train = pd.read_csv("data/train.csv", low_memory=False)
test = pd.read_csv("data/test.csv", low_memory=False)
y_train, y_test = train["Attack_type"], test["Attack_type"]

X_train = make_features(train).drop(columns=DROP)
X_test = make_features(test).drop(columns=DROP)

clf = RandomForestClassifier(
    n_estimators=100, n_jobs=-1, class_weight="balanced", random_state=42
)
clf.fit(X_train, y_train)
pred = clf.predict(X_test)

print("Dropped columns:", DROP)
print("Accuracy without them:", round(accuracy_score(y_test, pred), 4), "(earlier, all columns: 0.9419)")
print("Macro F1 without them:", round(f1_score(y_test, pred, average="macro"), 4), "(earlier: 0.894)")
print()
print(classification_report(y_test, pred, digits=3))

os.makedirs("models", exist_ok=True)
joblib.dump({"model": clf, "columns": list(X_train.columns)}, "models/clf_robust.joblib")
print("Saved models/clf_robust.joblib")
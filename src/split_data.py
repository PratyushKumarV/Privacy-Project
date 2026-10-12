import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_csv("data/ML-EdgeIIoT-dataset.csv", low_memory=False)

train, test = train_test_split(
    df, test_size=0.2, stratify=df["Attack_type"], random_state=42
)

train.to_csv("data/train.csv", index=False)
test.to_csv("data/test.csv", index=False)

print("Train:", len(train), "Test:", len(test))
print(test["Attack_type"].value_counts())
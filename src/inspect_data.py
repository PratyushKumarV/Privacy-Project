import pandas as pd

df = pd.read_csv("data/ML-EdgeIIoT-dataset.csv", low_memory=False)

print("Shape:", df.shape)
print("\nColumns:")
print(df.columns.tolist())
print("\nClass counts:")
print(df["Attack_type"].value_counts())
print("\nFirst 3 rows:")
print(df.head(3).T)
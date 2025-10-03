import pandas as pd
from pathlib import Path

RAW = Path("raw_data")
DST = Path("datasets")
DST.mkdir(exist_ok=True)

# ---- PAYSIM ----
paysim = RAW / "paysim" / "transactions.csv"
if paysim.exists():
    df = pd.read_csv(paysim)
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    sample = df.sample(min(len(df), 100_000), random_state=42)
    sample.to_parquet(DST / "paysim_sample.parquet", index=False)
    print("✔ paysim_sample.parquet")

# ---- SYNTHETIC (fraude cartão) ----
synthetic = RAW / "synthetic" / "credit_card_fraud.csv"
if synthetic.exists():
    df2 = pd.read_csv(synthetic)
    if "ts" in df2.columns:
        df2["ts"] = pd.to_datetime(df2["ts"], errors="coerce")
    df2.to_parquet(DST / "credit_card_fraud.parquet", index=False)
    print("✔ credit_card_fraud.parquet")

# ---- OpenSanctions (PEP sample) ----
pep = Path("datasets") / "opensanctions_pep_sample.csv"
if pep.exists():
    df3 = pd.read_csv(pep)
    df3.to_parquet(DST / "opensanctions_pep_sample.parquet", index=False)
    print("✔ opensanctions_pep_sample.parquet")

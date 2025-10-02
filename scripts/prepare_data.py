import pandas as pd
from pathlib import Path

RAW = Path("raw_data")
DST = Path("datasets")
DST.mkdir(exist_ok=True)

# Exemplo: se depois você colocar um CSV do PaySim em raw_data/paysim/
paysim_csv = RAW / "paysim" / "transactions.csv"
if paysim_csv.exists():
    df = pd.read_csv(paysim_csv)
    # crie uma amostra para desenvolvimento rápido
    sample = df.sample(min(100000, len(df)), random_state=42)
    sample.to_parquet(DST / "paysim_sample.parquet", index=False)
    print("OK: paysim_sample.parquet")

# Repita padrões parecidos para outros arquivos em raw_data/synthetic/

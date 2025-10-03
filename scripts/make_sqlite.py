import sqlite3
from pathlib import Path
import pandas as pd

DATASETS = Path("datasets")
DBPATH = Path("data/aml.db")
DBPATH.parent.mkdir(exist_ok=True, parents=True)

# Carrega o parquet gerado no Dia 2
df = pd.read_parquet(DATASETS / "paysim_sample.parquet").copy()

# Normaliza colunas esperadas (ajuste se seu CSV real tiver nomes diferentes)
expected = ["ts","cpf","device_id","ip","asn","city","amount","currency",
            "channel","merchant_id","beneficiary_id","type"]
for col in expected:
    if col not in df.columns:
        df[col] = None

# Converte ts para ISO8601 texto (SQLite trabalha bem com datetime() sobre strings ISO)
df["ts"] = pd.to_datetime(df["ts"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")

# Cria/conecta ao banco
con = sqlite3.connect(DBPATH)

# Tabela de transações (drop/recreate)
cur = con.cursor()
cur.executescript("""
DROP TABLE IF EXISTS transactions;

CREATE TABLE transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT,                -- ISO8601 "YYYY-MM-DD HH:MM:SS"
  cpf TEXT,
  device_id TEXT,
  ip TEXT,
  asn TEXT,
  city TEXT,
  amount REAL,
  currency TEXT,
  channel TEXT,
  merchant_id TEXT,
  beneficiary_id TEXT,
  type TEXT
);

CREATE INDEX idx_tx_cpf_ts   ON transactions(cpf, ts);
CREATE INDEX idx_tx_ts       ON transactions(ts);
CREATE INDEX idx_tx_device   ON transactions(device_id);
CREATE INDEX idx_tx_ip       ON transactions(ip);
CREATE INDEX idx_tx_city_asn ON transactions(city, asn);
""")
con.commit()

df[["ts","cpf","device_id","ip","asn","city","amount","currency",
    "channel","merchant_id","beneficiary_id","type"]].to_sql(
    "transactions", con, if_exists="append", index=False
)

# Vacuum para compactar
cur.execute("VACUUM;")
con.commit()
con.close()
print("✔ SQLite pronto em data/aml.db com tabela 'transactions'")

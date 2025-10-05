# Blue Team AML Portfolio

Portfólio prático focado em **cibersegurança defensiva**, cobrindo **antifraude/AML**, **Pandas/SQL para detecção**, e **DFIR (Volatility 3)**.  
Objetivo: demonstrar **desenho de regras**, **tuning baseado em dados**, e **investigação forense** com entrega executiva de achados.

## 🧩 Conteúdo
- `pandas/01_eda.ipynb`: EDA do dataset (PaySim sintético) e preparação de features.
- `reports/alerts/...`: Saídas de regras AML (ex.: **Regra C – burst 1h por CPF**).
- `reports/dfir/`: Artefatos do **Reveal Lab** (Volatility 3) — cmdline, netscan, dlllist, timeliner.
- `reports/IR_Reveal.md`: Relatório curto (sumário executivo, achados, recomendações).

## ⚙️ Como rodar (local)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # ou: pip install pandas pyarrow matplotlib jupyter
jupyter notebook

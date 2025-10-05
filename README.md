# Blue Team AML Portfolio

Portfólio prático focado em **cibersegurança defensiva**, cobrindo **antifraude/AML**, **Pandas/SQL** para detecção e **DFIR (Volatility 3)**.
**Objetivo:** demonstrar desenho de **regras**, **tuning baseado em dados** e **investigação forense** com entrega executiva de achados**.

## 🔎 Highlights (o que este repo prova)

* **Regras AML com Pandas/SQL**: janela móvel, agregações, enriquecimento e consolidação de alertas.
* **DFIR de memória (Volatility 3)**: identificação de **LOLBAS** (PowerShell oculto + WebDAV + `rundll32`), conexões externas e persistência provável.
* **Entrega executiva**: relatórios curtos e reprodutíveis; artefatos versionados.
* **Higiene de engenharia**: estrutura clara, reprodutibilidade local, prontidão para evoluir regras e métricas.

---

## 🧩 Conteúdo do repositório

```
.
├── data/                     # dados (ex.: paysim.parquet)
├── pandas/                   # notebooks (EDA, regras, tuning)
│   └── 01_eda.ipynb
├── reports/
│   ├── alerts/               # CSVs de alertas gerados (A/B/C + consolidado)
│   ├── dfir/                 # artefatos do Volatility (cmdline, netscan, dlllist...)
│   └── IR_Reveal.md          # relatório completo do lab Reveal (DFIR)
├── tests/                    # amostras mínimas p/ testar regras A/B
└── README.md
```

---

## ⚙️ Como rodar localmente

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pandas pyarrow jupyter
jupyter notebook
```

Abra `pandas/01_eda.ipynb`. O dataset sintético está em `data/paysim.parquet`.

---

## 🧠 Rule Pack (v1) — AML & DFIR

### C) AML — Burst 1h por CPF (entrega ativa)

**Ideia:** sinalizar clientes com volume/valor **atípico** em janela de **60min**.
**Lógica (exemplo):**

* `tx_count_60m >= 4` **ou** `amount_sum_60m >= 1000`
  **Saída:** `reports/alerts/dayX_ruleC_aml_burst_1h.csv` (tem pelo menos 1 linha no dataset de exemplo).
  **Uso didático:** mostra **agregação temporal**, **perfil por cliente** e geração de **alertas reproduzíveis**.

### A) DFIR — WebDAV + rundll32 + PowerShell oculto (ampliada)

**Ideia:** detectar **LOLBAS** (execução via Living-off-the-Land).
**Fontes:** `cmdline` do Volatility + amostra em `tests/dfir_cmdline_samples.txt`.
**Status:** **0 hits nos artefatos originais** (sessão possivelmente fora da captura), **1 hit** nas **amostras de teste** (prova de conceito).
**Saída:** `reports/alerts/dayX_ruleA_webdav_rundll32_ext.csv`.

### B) DFIR — svchost.exe → HTTP externo (porta 80/8000/8080/8888)

**Ideia:** sinalizar **svchost** falando com **IP público em portas HTTP** (comum em abuso).
**Fontes:** `netscan` do Volatility + amostra em `tests/dfir_netscan_samples.txt`.
**Status:** **0 hits nos artefatos originais** (recorte não capturou), **1 hit** nas **amostras de teste** (prova de conceito).
**Saída:** `reports/alerts/dayX_ruleB_svchost_http_like_external.csv`.

---

## 🕵️ DFIR (Reveal / Volatility 3)

* **Relatório completo:** [`reports/IR_Reveal.md`](reports/IR_Reveal.md)
* **Artefatos:** [`reports/dfir/`](reports/dfir/) (cmdline, netscan, dlllist, timeliner, extracts)

**Resumo dos achados:**

* **LOLBAS confirmado:** `powershell.exe -windowstyle hidden` + `net use` WebDAV + `rundll32` de **DLL remota**.
* **Rede externa:** `svchost.exe (PID 1260)` com **HTTP** → `196.204.4.8:80`.
* **Persistência provável:** **Scheduled Task** `{ED77AEE0-EAFB-4133-B544-9E7C5632D902}`.
* **Recomendações:** bloquear IOCs, habilitar Script Block Logging, ASR contra abuso de `rundll32`/WebDAV, WDAC/AppLocker.

---

## 🧪 Reprodutibilidade (testes mínimos)

* **Amostras** em `tests/` garantem que as Regras **A/B** gerem **pelo menos 1 alerta** em ambiente controlado, provando a **lógica e scoring**.

---


## 📚 Datasets

* **PaySim (sintético)** em `data/paysim.parquet` — base para regras AML (C) e evolução.



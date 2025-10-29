# Reveal DFIR Volatility3 AML

> **IR - Análise de Memória (Reveal Lab — Cyber Defenders)**  
> **Lab:** https://cyberdefenders.org/blueteam-ctf-challenges/reveal/
> 

## 1) Sumário Executivo

**Contexto**  
Estação Windows com acesso a dados financeiros foi sinalizada pelo SIEM por possível atividade anômala. Para confirmação de comprometimento e orientação da contenção, foi coletado um **dump de memória** da máquina.

**Escopo**  
Identificar **processos/linhas de comando**, **conexões externas**, sinais de **injeção/persistência** e montar uma **timeline** do incidente.

**Escopo & abordagem Reveal Lab (resumo)**  
- **Objetivo:** compreender **natureza**, **sistemas afetados**, **cronologia** e **impacto** para mitigar risco e endereçar **causa-raiz**.  
- **Âmbito:** alerta do **SIEM** em estação com dados financeiros; **artefato** analisado: dump de memória (~2 GB) de **Windows 10**.  
- **Ferramenta:** **Volatility 3** (arquitetura de plugins + tabelas de símbolos) para interpretar estruturas do SO e extrair evidências.

**Relatório completo:**
➡️ [reports/IR_Reveal.md](https://github.com/The-Black-Needles/case02-reveal-dfir-volatility3-aml/blob/main/reports/IR_Reveal.md)

---

## 2) Sobre este repositório

Portfólio prático focado em cibersegurança defensiva, cobrindo **antifraude/AML**, **Pandas/SQL** para detecção e **DFIR** (Volatility 3).  
**Objetivo:** demonstrar **desenho de regras**, **tuning baseado em dados** e **investigação forense** com **entrega executiva** de achados.

### 🔎 Highlights (o que este repo prova)
- **Regras AML com Pandas/SQL:** janela móvel, agregações, enriquecimento e **consolidação de alertas**.  
- **DFIR de memória (Volatility 3):** identificação de **LOLBAS** (PowerShell oculto + WebDAV + rundll32), **conexões externas** e **persistência** provável.  
- **Entrega executiva:** relatórios curtos e **reprodutíveis**; artefatos **versionados**.  
- **Higiene de engenharia:** estrutura clara, execução local simples, prontidão para **evoluir regras e métricas**.

---

## 3) Stack & Pipeline

**Stack:** Volatility 3 (DFIR), Python **Pandas/SQL** (regras AML), Jupyter Notebooks, SQLite.  

**Pipeline (alto nível):**
1. Coleta/artefato (dump de memória)  
2. **Detecção DFIR** (cmdline, rede, módulos)  
3. **Detecção AML** (regras de burst por CPF/tempo)  
4. **Investigação & correlação** (timeline, IoCs)  
5. **Documentação & ajuste** (relatório, versões, testes)

---

## 4) Conteúdo do repositório

```
.
├── data/                     # dados (ex.: paysim.parquet)
├── notebooks/                # notebooks (EDA, regras, tuning)
│   └── 01_eda.ipynb
├── reports/
│   ├── alerts/               # CSVs de alertas gerados (A/B/C + consolidado)
│   ├── dfir/                 # artefatos do Volatility (cmdline, netscan, dlllist...)
│   └── IR_Reveal.md          # relatório completo do lab Reveal (DFIR)
├── tests/                    # amostras mínimas p/ testar regras A/B
├── SECURITY.md
└── README.md
```

---

## 5) 🧪 Reprodutibilidade - GitHub Codespaces 

Abra o repositório no GitHub → Code → Create codespace on main.
No terminal do Codespaces:

```bash
pip install -r requirements.txt
python scripts/run_rules_min.py
```

Abra notebooks/01_eda.ipynb pelo Jupyter do Codespaces.
- **Notebooks** em `notebooks/` (receita passo a passo)  
- **CSVs** em `reports/` (resultados abríveis como planilha)  
- **Versionamento** no GitHub (histórico de mudanças)  
- **Harness de testes** em `tests/` (amostras sintéticas) para validar detecções **sem alterar** evidências reais.
  
---

## 6) 🧠 Rule Pack (v1) — AML & DFIR

**A) DFIR — WebDAV + rundll32 + PowerShell oculto (ampliada)**  
- **Ideia:** detectar **LOLBAS** (execução Living-off-the-Land).  
- **Fontes:** \`reports/dfir/cmdline.txt\` + amostra em \`tests/dfir_cmdline_samples.txt\`.  
- **Status:** 0 hits nos artefatos originais (sessão possivelmente fora da captura); **1 hit** nas amostras de teste (**prova de conceito**).  
- **Saída:** \`reports/alerts/dayX_ruleA_webdav_rundll32_ext.csv\`.

**B) DFIR — svchost.exe → HTTP externo (80/81/8000/8080/8888)**  
- **Ideia:** sinalizar \`svchost.exe\` falando com **IP público** em portas HTTP (padrão comum de abuso).  
- **Fontes:** \`reports/dfir/netscan.txt\` + amostra em \`tests/dfir_netscan_samples.txt\`.  
- **Status:** 0 hits no recorte original; **1 hit** nas amostras de teste (prova de conceito).  
- **Saída:** \`reports/alerts/dayX_ruleB_svchost_http_like_external.csv\`.

**C) AML — Burst 1h por CPF (entrega ativa)**  
- **Ideia:** sinalizar clientes com **volume/valor atípico** em janela de **60 min**.  
- **Lógica (exemplo):** \`tx_count_60m >= 4\` **ou** \`amount_sum_60m >= 1000\`.  
- **Saída:** \`reports/alerts/dayX_ruleC_aml_burst_1h.csv\` (dataset exemplo possui ≥1 linha).  
- **Uso didático:** mostra **agregação temporal**, **perfil por cliente** e **alertas reprodutíveis**.

---

## 7) 🕵️ DFIR (Reveal / Volatility 3)

- **Relatório completo:** \`reports/IR_Reveal.md\`  
- **Artefatos:** \`reports/dfir/\` (cmdline, netscan, dlllist, timeliner, extracts)

**Resumo dos achados**
- **LOLBAS confirmado:** \`powershell.exe -windowstyle hidden\` + \`net use\` WebDAV + \`rundll32\` de DLL remota.  
- **Rede externa:** \`svchost.exe\` (PID 1260) com HTTP → \`196.204.4.8:80\`.  
- **Persistência provável:** **Scheduled Task** \`{ED77AEE0-EAFB-4133-B544-9E7C5632D902}\`.  

**Recomendações**  
Bloquear IOCs; habilitar **Script Block Logging**; **ASR** contra abuso de \`rundll32\`/WebDAV; **WDAC/AppLocker**.

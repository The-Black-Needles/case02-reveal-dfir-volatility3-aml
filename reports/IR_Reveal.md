# IR - Análise de Memória (Template Reveal)

## 1. Sumário executivo
- Contexto:
- Escopo:
- Achados-chave:

## 2. Metodologia
- Ferramenta: Volatility 3 (plugins: pslist, pstree, netscan, dlllist, handles, malfind, timeliner)
- Imagem analisada:
- Data/hora:

## 3. Evidências principais
- Processos suspeitos (pslist/pstree):
- Conexões de rede (netscan):
- Injeções/Regiões suspeitas (malfind):
- Bibliotecas e handles relevantes (dlllist/handles):

## 4. Timeline do incidente
- (trechos do timeliner + interpretação)

## 5. Conclusões e recomendações
- Causa provável:
- Contenção/Remediação:
- Limitações da análise:
- Lições aprendidas:

## 6. Arquivos de evidência
- windows_info.txt
- pslist.txt
- pstree.txt
- netscan.txt
- dlllist_all.txt
- handles.txt
- malfind.txt
- timeliner.txt

---

## 3. Evidências principais — Extracts (auto-gerado)

### 3.1 Processos e hierarquia
- Linhas suspeitas (pslist): reports/dfir/findings/pslist_suspect.txt  
- Linhas suspeitas (pstree): reports/dfir/findings/pstree_suspect.txt  
- PIDs mais frequentes: reports/dfir/findings/pids_frequentes.txt

### 3.2 Conexões de rede
- Conexões externas: reports/dfir/findings/netscan_external.txt  
- Endpoints remotos (únicos): reports/dfir/findings/netscan_remote_endpoints.txt  
- PIDs com rede externa: reports/dfir/findings/netscan_pids.txt

### 3.3 DLLs / Handles
- DLLs em locais incomuns: reports/dfir/findings/dlls_incomuns.txt  
- Handles suspeitos: reports/dfir/findings/handles_suspeitos.txt

### 3.4 Injeções / Regiões anômalas
- Hits do malfind: reports/dfir/findings/malfind_hits.txt  
- PIDs citados no malfind: reports/dfir/findings/malfind_pids.txt

### 3.5 Cruzamento de sinais
- PIDs em rede externa **e** malfind: reports/dfir/findings/pids_intersec_net_mal.txt  
- PIDs em rede externa **e** frequentes (processos suspeitos): reports/dfir/findings/pids_intersec_net_freq.txt

> Use os arquivos acima como base para preencher as seções 3.1–3.4 com **nomes de processo, PIDs, caminhos e horários**. Em seguida, referencie 2–3 linhas do timeliner na Seção 4 para construir a **narrativa do incidente**.

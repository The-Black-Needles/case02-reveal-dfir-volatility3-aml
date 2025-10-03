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

---

## 3. Evidências principais — Análise (baseada nos artefatos reais)

> Fontes: `reports/dfir/pslist.txt`, `pstree.txt`, `netscan.txt`, `malfind.txt`, `timeliner.txt`  
> Extracts gerados: `reports/dfir/findings/*` (vide seção “Extracts (auto-gerado)”)

### 3.1 Processos e hierarquia (pslist / pstree)
- Em `pstree.txt`, foram observados **múltiplos filhos de `msedge.exe`** (PPID **5488**) com criação em **2024-07-15 04:02–06:58 UTC** e `--type=renderer/utility`, compatível com navegação normal:
  - Exemplos: `msedge.exe` **PID 6404** (2024-07-15 06:58:52), **PID 4464** (renderer, 04:17:28), **PID 1880** (renderer, 04:19:01), **PID 5780** (utility network service, 10:45:14, 2024-07-04).
- Processos de sistema iniciais aparecem normais (de acordo com `pstree.txt` próximo ao topo):
  - `System` (PID 4), `smss.exe` (PID 300), `csrss.exe` (PID 416), `wininit.exe` (PID 492), além de `MemCompression` e `Registry`.
- **Ponto de atenção**: `WWAHost.exe` (PID **6780**) aparece em conexões externas (ver 3.2).  
- **Ponto de atenção**: `svchost.exe` com **múltiplas conexões externas** (PIDs **440** e **1260**) — comportamento que merece validação do papel desses serviços (ver 3.2).

**Leitura rápida**: ver `reports/dfir/findings/pstree_suspect.txt` para as linhas da árvore contendo “edge/renderer/utility” e `pids_frequentes.txt` para PIDs recorrentes.

---

### 3.2 Conexões de rede (netscan)
Do `netscan.txt` (amostras filtradas em `netscan_external.txt`), foram observadas conexões **externas**:

- **smartscreen.exe (PID 2820)** → `191.237.206.80:443` — **ESTABLISHED** (2024-07-15 06:59:57).  
  *Comentário*: tráfego possivelmente legítimo (Microsoft SmartScreen).
- **WWAHost.exe (PID 6780)** → `13.107.6.156:443` e `93.186.134.98:443` — **ESTABLISHED** (2024-07-04 10:46:50–51).  
  *Comentário*: `13.107.6.156` tende a ser infraestrutura Microsoft; `93.186.134.98` requer enriquecimento (pode ser CDN/terceiro).
- **svchost.exe (PID 440)** → `13.74.129.92:443`, `23.44.141.39:443` — **ESTABLISHED** (2024-07-15 06:58:24–25).  
  *Comentário*: IPs que costumam ser MS/Akamai; ainda assim, confirmar qual serviço do `svchost` originou a sessão.
- **svchost.exe (PID 1260)** → `196.204.4.8:80` — **ESTABLISHED** (2024-07-15 06:59:22).  
  *Comentário*: **incomum**: `svchost` abrindo **HTTP (porta 80)** para endereço **externo** não interno. **Requer verificação** (whois/reverso, reputação).

**Conclusão parcial 3.2**: embora parte do tráfego pareça alinhado a componentes Microsoft, o **`svchost.exe` PID 1260 → 196.204.4.8:80** é **sinal forte** para investigação (possível C2/exfil/telemetria indevida via serviço).

---

### 3.3 Bibliotecas/Handles (dlllist / handles)
- Não foram apresentados trechos suspeitos específicos nos extratos enviados. Recomenda-se revisar:
  - `reports/dfir/findings/dlls_incomuns.txt` (DLLs carregadas fora de diretórios do sistema; ex.: `AppData\*, Temp\*, ProgramData\*`).
  - `reports/dfir/findings/handles_suspeitos.txt` (pipes/arquivos/chaves de registro atípicos).
- **Se** `svchost.exe` (PID 1260) carregar DLLs de caminhos de usuário/Temp, isso corrobora hipótese de abuso/implantação.

---

### 3.4 Injeções / Regiões anômalas (malfind)
- O trecho enviado de `malfind.txt` não trouxe cabeçalhos claros de **PID/processo** relacionados a `msedge/WWAHost/svchost`. Houve apenas um bloco hexadecimal não atribuível (“PID 07”, que não é um PID válido).  
- **Leitura recomendada**: procurar explicitamente por `svchost.exe (PID 1260)` e `WWAHost.exe (PID 6780)` dentro do `malfind.txt`.  
- **Status atual**: **sem evidência conclusiva de injeção** nos PIDs destacados a partir do conteúdo fornecido. (Pode haver evidência no arquivo completo — revisar com busca por “Pid 1260”, “Pid 6780”, ou pelo nome do processo).

**Conclusão parcial (sec. 3)**: a correlação mais forte até aqui é **processo de serviço (`svchost.exe`, PID 1260)** com **rede externa não trivial (HTTP em 196.204.4.8:80)** no mesmo intervalo temporal em que múltiplos `msedge.exe` circulam. Prioridade: **investigar o serviço/role do `svchost` PID 1260** (qual `svchost`/SVC, qual DLL de serviço carregada, cmdline, chaves de execução, etc.).

---

## 4. Timeline do incidente (timeliner) — Narrativa

> Fonte: `reports/dfir/timeliner.txt` (linhas exibidas no seu extrato)

1. **2024-07-04 10:44:50 UTC** — Múltiplos **`svchost.exe`** iniciados (PIDs 764 e 872) por `WORKGROUP/DESKTOP-T51LU0E$` (entradas de `PsList/Sessions`).  
2. **2024-07-04 10:45:14 UTC** — Atividade de `msedge.exe` (utility network service) é registrada (coerente com navegação).  
3. **2024-07-15 06:58:24–25 UTC** — **`svchost.exe` (PID 440)** estabelece conexões TLS externas (`13.74.129.92:443` e `23.44.141.39:443`).  
4. **2024-07-15 06:59:22 UTC** — **`svchost.exe` (PID 1260)** estabelece conexão **HTTP** para **`196.204.4.8:80`** (ponto mais suspeito até aqui).  
5. **2024-07-15 07:00:00 UTC** — `timeliner` registra **criação de tarefa agendada** (`{ED77AEE0-EAFB-4133-B544-9E7C5632D902}`), possivelmente **persistência** a validar (qual ação, qual binário/argumentos?).

> Observação: não há (nos trechos apresentados) evidência clara de `malfind` para os PIDs acima; contudo, a combinação **svchost + HTTP externo + tarefa agendada próxima** é **compatível** com cadeia de persistência/comunicação.

**Próximos passos sugeridos:**
- Mapear **qual serviço** roda dentro de `svchost.exe` (PID **1260**) e sua **DLL** (ex.: `windows.dlllist --pid 1260`, `windows.getsids`, `windows.cmdline`, `windows.services`).  
- Enriquecer **`196.204.4.8`** (whois, passive DNS, reputação TI) e checar indicadores associados.  
- Confirmar a **tarefa `{ED77AEE0-…}`**: ação, comando, caminho do binário, usuário, frequência (plugins de registry/scheduled tasks).


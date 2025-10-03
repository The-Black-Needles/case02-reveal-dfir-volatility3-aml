#!/usr/bin/env bash
set -euo pipefail

IMG="${1:-raw_data/dfir/192-Reveal.dmp}"
OUT="reports/dfir"
mkdir -p "$OUT"

# Descobrir comando volatility3
if command -v vol >/dev/null 2>&1; then
  VOL="vol"
elif command -v python >/dev/null 2>&1; then
  VOL="python -m volatility3"
else
  echo "Volatility3 não encontrado. Ative o venv ou instale via pip." >&2
  exit 1
fi

echo "[*] Image: $IMG"
echo "[*] Output dir: $OUT"
echo "[*] Using: $VOL"

# Teste de info do sistema/automagic
echo "[*] windows.info"
$VOL -f "$IMG" windows.info | tee "$OUT/windows_info.txt" || true

# Processos
echo "[*] windows.pslist"
$VOL -f "$IMG" windows.pslist | tee "$OUT/pslist.txt" || true

echo "[*] windows.pstree"
$VOL -f "$IMG" windows.pstree | tee "$OUT/pstree.txt" || true

# Redes
echo "[*] windows.netscan"
$VOL -f "$IMG" windows.netscan | tee "$OUT/netscan.txt" || true

# DLLs/handles (podem gerar MUITA saída; salvamos tudo e mostramos só cabeçalho)
echo "[*] windows.dlllist (amostra)"
$VOL -f "$IMG" windows.dlllist | tee "$OUT/dlllist_all.txt" >/dev/null || true
head -n 50 "$OUT/dlllist_all.txt" || true

echo "[*] windows.handles (amostra)"
$VOL -f "$IMG" windows.handles | tee "$OUT/handles.txt" >/dev/null || true
head -n 50 "$OUT/handles.txt" || true

# Heurística de injeções
echo "[*] windows.malfind (amostra)"
$VOL -f "$IMG" windows.malfind | tee "$OUT/malfind.txt" >/dev/null || true
head -n 50 "$OUT/malfind.txt" || true

# Timeline consolidada
echo "[*] timeliner (amostra)"
$VOL -f "$IMG" timeliner | tee "$OUT/timeliner.txt" >/dev/null || true
head -n 50 "$OUT/timeliner.txt" || true

echo "[*] DONE - artefatos em $OUT"

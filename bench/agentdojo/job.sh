#!/bin/bash
# AgentDojo x homestead-gate on any single-GPU Linux box (Kaggle T4, Lightning, a rented GPU).
# Env: SUITE, TASKS (space-separated user task ids), SETTINGS (space-separated, see below), LANES (default 3),
#      RES (results dir, default ./res). Expects run_gate.py and review.py next to it under bench/ (the
#      kaggle_kernel.py wrapper writes them), or fetches them from GitHub at $REV.
# LANES parallel run_gate processes share one Ollama (OLLAMA_NUM_PARALLEL=LANES); each gets its own task
# slice and output dir, so AgentDojo's per-task logs never collide. Progress goes to stdout every 3 min,
# because on most hosts the job log is the only window into a running job.
set -uo pipefail
REV=${REV:-master}
LANES=${LANES:-3}
RES=${RES:-$PWD/res}
MODEL=qwen3.5:9b
AGENT=qwen3.5-9b-agent16k

(apt-get update -qq && apt-get install -y -qq curl zstd ca-certificates) >/dev/null 2>&1 || true
command -v ollama >/dev/null || curl -fsSL https://ollama.com/install.sh | sh >/dev/null 2>&1
if ! curl -sf localhost:11434/api/version >/dev/null; then
  OLLAMA_NUM_PARALLEL=$LANES OLLAMA_CONTEXT_LENGTH=16384 OLLAMA_KEEP_ALIVE=60m nohup ollama serve >/tmp/ollama.log 2>&1 &
  for i in $(seq 60); do curl -sf localhost:11434/api/version >/dev/null && break; sleep 2; done
fi
for i in $(seq 8); do ollama pull $MODEL >/dev/null 2>&1 && break; sleep 150; done   # registry sometimes 524s
printf 'FROM %s\nPARAMETER num_ctx 16384\nPARAMETER temperature 0\n' "$MODEL" > /tmp/Modelfile
ollama create $AGENT -f /tmp/Modelfile >/dev/null
pip install -q agentdojo==0.1.35 openai
mkdir -p bench/agentdojo
[ -f bench/review.py ] || curl -fsSL https://raw.githubusercontent.com/fuckbigtech-ai/homestead-gate/$REV/bench/review.py -o bench/review.py
[ -f bench/agentdojo/run_gate.py ] || curl -fsSL https://raw.githubusercontent.com/fuckbigtech-ai/homestead-gate/$REV/bench/agentdojo/run_gate.py -o bench/agentdojo/run_gate.py
echo "run_gate $(sha256sum bench/agentdojo/run_gate.py | cut -c1-12) review $(sha256sum bench/review.py | cut -c1-12)"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader

read -ra ALL <<< "$TASKS"
( while sleep 180; do echo "=== PROGRESS $(date -u +%H:%M) runs_done=$(find "$RES" -path '*agentdojo_logs*' -name '*.json' 2>/dev/null | wc -l)"; done ) &
for S in $SETTINGS; do
  case $S in
    nogate)         X="";;
    gate)           X="--gate $AGENT --human none";;
    gate_oracle)    X="--gate $AGENT --human oracle";;
    gate_v*)        X="--gate $AGENT --human none --prompt ${S#gate_}";;
    gate_oracle_v*) X="--gate $AGENT --human oracle --prompt ${S#gate_oracle_}";;
    *) echo "unknown setting $S"; continue;;
  esac
  T0=$(date +%s); PIDS=()
  for ((L=0; L<LANES; L++)); do
    MINE=(); for ((i=L; i<${#ALL[@]}; i+=LANES)); do MINE+=("${ALL[$i]}"); done
    [ ${#MINE[@]} -eq 0 ] && continue
    python bench/agentdojo/run_gate.py --suite "$SUITE" --agent $AGENT --out "$RES/$S/lane$L" \
      --user-tasks "${MINE[@]}" $X > "/tmp/run_${S}_$L.log" 2>&1 &
    PIDS+=($!)
  done
  RC=0; for p in "${PIDS[@]}"; do wait "$p" || RC=$?; done
  echo "=== SETTING $S rc=$RC minutes=$(( ($(date +%s)-T0)/60 )) lanes=$LANES tasks=${#ALL[@]}"
  for f in /tmp/run_${S}_*.log; do tail -2 "$f"; done
done
echo "=== DONE"

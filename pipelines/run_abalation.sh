#!/usr/bin/env bash
# run_abalation.sh — run ablation experiments across models and augmentation subsets
#
# Usage:
#   ./run_abalation.sh llama3         # run all 5 augment subsets for llama3:8b
#   ./run_abalation.sh deepseek       # run all 5 augment subsets for deepseek-coder:6.7b
#   ./run_abalation.sh mistral        # run all 5 augment subsets for mistral
#   ./run_abalation.sh all            # run all models x all subsets
#
# Optional env overrides:
#   OLLAMA_HOST=http://host:port ./run_abalation.sh llama3
#   VA_HOST=http://host:port    ./run_abalation.sh llama3
#   CANDIDATES=5                 ./run_abalation.sh llama3   # Pass@5

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE="$SCRIPT_DIR/abalation_pipeline.py"

OLLAMA_HOST="${OLLAMA_HOST:-http://100.97.159.90:11434}"
VA_HOST="${VA_HOST:-http://100.78.242.59:8000}"
CANDIDATES="${CANDIDATES:-1}"
# Default temperature: greedy for pass@1, diverse for pass@k
if [ -z "${TEMPERATURE:-}" ]; then
    TEMPERATURE=$( [ "$CANDIDATES" -eq 1 ] && echo "0.01" || echo "0.8" )
fi
SEED="${SEED:-42}"
# Single timestamp for the whole bash run so all augment files share a folder
RUN_DIR="${SCRIPT_DIR}/experiments/$(date '+%Y-%m-%d_%H-%M-%S')"

AUGMENTS=(
    "vanilla"
    "loc"
    "loc,retrieval"
    "loc,type"
    "all"
)

run_model() {
    local model="$1"
    echo ""
    echo "=========================================="
    echo "Model: $model"
    echo "=========================================="

    for augment in "${AUGMENTS[@]}"; do
        echo ""
        echo "--- Augment: $augment ---"
        python3 "$PIPELINE" \
            --model        "$model" \
            --augment      "$augment" \
            --candidates   "$CANDIDATES" \
            --temperature  "$TEMPERATURE" \
            --seed         "$SEED" \
            --ollama-host  "$OLLAMA_HOST" \
            --va-host     "$VA_HOST" \
            --run-dir      "$RUN_DIR"
    done
}

case "${1:-}" in
    llama3)
        run_model "llama3:8b"
        ;;
    deepseek)
        run_model "deepseek-coder:6.7b"
        ;;
    mistral)
        run_model "mistral"
        ;;
    all)
        run_model "llama3:8b"
        run_model "deepseek-coder:6.7b"
        run_model "mistral"
        ;;
    *)
        echo "Usage: $0 {llama3|deepseek|mistral|all}"
        echo ""
        echo "  llama3    — llama3:8b"
        echo "  deepseek  — deepseek-coder:6.7b"
        echo "  mistral   — mistral"
        echo "  all       — run all three models x all 5 augment subsets"
        echo ""
        echo "Optional env overrides:"
        echo "  OLLAMA_HOST=http://host:port  (default: http://100.97.159.90:11434)"
        echo "  VA_HOST=http://host:port     (default: http://100.78.242.59:8001)"
        echo "  CANDIDATES=5                  (default: 1, use 5 for Pass@5)"
        echo "  TEMPERATURE=0.8               (default: 0.01 for pass@1, 0.8 for pass@k)"
        echo "  SEED=42                       (default: 42)"
        exit 1
        ;;
esac

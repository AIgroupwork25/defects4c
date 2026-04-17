# Replication Guide — Ablation Study

This guide describes how to fully replicate the experimental setup and run the ablation pipeline on the Defects4C benchmark.

---

## Prerequisites

- Linux host machine (tested on Ubuntu 22.04)
- Docker installed
- At least **80 GB** free disk space
- At least **50 GB** RAM recommended
- A running **Ollama** instance serving the LLM models under evaluation
- A running **VA** server (fault localisation/classification/retrieval service)
- Python 3.8+ on the host machine

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/jiasing/defect4Cpure.git
cd defect4Cpure
```

---

## Step 2 — Build the Docker image

```bash
docker image build -t base/defect4c .
```

---

## Step 3 — Start the container

```bash
docker run -d \
  --name my_defects4c \
  --ipc=host \
  --cap-add SYS_PTRACE \
  -p 11111:80 \
  -v "$(pwd)/defectsc_tpl:/src" \
  -v "$(pwd)/out_tmp_dirs:/out" \
  -v "$(pwd)/patche_dirs:/patches" \
  -v "$(pwd)/LLM_Defects4C:/src2" \
  base/defect4c:latest
```

Port `11111` on the host maps to port `80` inside the container.

---

## Step 4 — Clone the benchmark repositories

This downloads all C/C++ project repositories (excluding LLVM) into `out_tmp_dirs/`. Requires approximately 80 GB of disk space.

```bash
docker exec my_defects4c bash -lc 'cd /src && bash bulk_git_clone_v2.sh'
```

---

## Step 5 — Run the warmup

This compiles each project at each bug-fix commit so that test cases are ready to execute. Pass the number of parallel jobs as an argument (8 is recommended).

```bash
docker exec my_defects4c bash -lc 'cd /src && bash run_warmup.sh 8'
```

Expected duration: approximately 20 minutes on a machine with 8+ cores.

> Note: Running with fewer parallel jobs (e.g. `run_warmup.sh 2`) will significantly increase the duration (2+ hours).

---

## Step 6 — Start the local API server

The Defects4C evaluation API must be running inside the container before executing any pipeline. A helper script is provided:

```bash
bash run_localserver.sh
```

This installs the required Python dependencies (`uvicorn`, `fastapi`, `pandas`, `jinja2`, `jmespath`, `redis`) and starts the FastAPI server on port 80 inside the container. It will print `Server is up at http://127.0.0.1:11111` when ready.

To verify the server is running:

```bash
curl http://127.0.0.1:11111/list_defects_bugid
```

Expected: a JSON response listing 263 defect IDs.

---

## Step 7 — Install host-side Python dependencies

The ablation pipeline runs on the host machine (not inside the container).

```bash
pip install openai requests
```

---

## Step 8 — Run the ablation pipeline

The pipeline is located in `pipelines/`. The launcher script `run_abalation.sh` runs all five augmentation subsets for a given model.

### Single model

```bash
cd pipelines
./run_abalation.sh llama3      # llama3:8b
./run_abalation.sh deepseek    # deepseek-coder:6.7b
./run_abalation.sh mistral     # mistral
```

### All models

```bash
./run_abalation.sh all
```

### Optional environment variable overrides

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://100.97.159.90:11434` | Ollama server URL |
| `VA_HOST` | `http://100.78.242.59:8000` | VA API server URL |
| `CANDIDATES` | `1` | Number of patch candidates per bug (set to `5` for Pass@5) |
| `TEMPERATURE` | `0.01` (Pass@1) / `0.8` (Pass@k) | Sampling temperature |
| `SEED` | `42` | Random seed for reproducibility |

Example — run with a custom Ollama host and Pass@5:

```bash
OLLAMA_HOST=http://myserver:11434 CANDIDATES=5 ./run_abalation.sh deepseek
```

---

## Augmentation subsets

The pipeline evaluates five conditions, each adding progressively more context from the VA API:

| Label | `--augment` value | VA outputs injected |
|---|---|---|
| Vanilla | `vanilla` | None (baseline) |
| +Loc | `loc` | Fault localisation → system message |
| +Loc+Retrieval | `loc,retrieval` | Localisation → system message; similar examples → user message |
| +Loc+Type | `loc,type` | Localisation + bug classification → system message |
| +All | `all` | Localisation + classification → system message; retrieval → user message |

---

## Output files

Each run produces one `.txt` file per augmentation condition, saved under:

```
pipelines/experiments/{timestamp}/{model}_{ablation}.txt
```

Each file contains:
- **Setup header** — model, ablation label, temperature, seed, candidates, base system prompt, VA augmentation applied
- **Per-patch blocks** — SHA, VA outputs for that bug, prompt sent to LLM (system and user messages), extracted patch, compile result, fix result
- **Summary footer** — total cases, compile rate, Pass@k rate

---

## Test cases

The pipeline evaluates on **52 CVE vulnerability test cases** from the Defects4C benchmark, drawn from all three granularity subsets in `buggy_errmsg_cve` (`single_function_repair`, `single_function_single_hunk_repair`, `single_function_single_line_repair`). Regardless of the original granularity label, the entire vulnerable function is extracted and fed to both the VA API and the LLM, so all 52 cases are treated uniformly as single-function repair tasks.

---

## Experimental configuration

| Parameter | Value |
|---|---|
| Benchmark | Defects4C (`buggy_errmsg_cve/`, all three granularity subsets) |
| Test cases | 52 CVE vulnerabilities |
| Repair granularity | Single function (full function provided in all cases) |
| Temperature | 0.01 (Pass@1) / 0.8 (Pass@5) |
| Seed | 42 |
| Max tokens | 4096 |
| Pass@k | 1 (default), 5 (optional) |

### Running Pass@1 (default)

The default configuration generates one patch candidate per bug with near-deterministic sampling (temperature 0.01):

```bash
./run_abalation.sh deepseek
```

### Running Pass@5

Pass@5 generates 5 independent patch candidates per bug and reports a bug as fixed if **any one** of the 5 candidates passes all test cases. To enable this, set `CANDIDATES=5`. Temperature is automatically raised to `0.8` to encourage diversity across candidates:

```bash
CANDIDATES=5 ./run_abalation.sh deepseek
```

Internally, the pipeline calls the LLM 5 times per bug, submits each resulting patch to the Defects4C `/fix` endpoint, and polls for results. A bug is counted as fixed (`Pass@5 = True`) as soon as one candidate succeeds — remaining candidates for that bug are skipped. This means Pass@5 runtime is up to 5x longer than Pass@1 in the worst case, but shorter when early candidates succeed.

> Note: Pass@5 results should be reported separately from Pass@1 results, as the temperature difference (0.01 vs 0.8) means the two configurations are not directly comparable on a per-patch basis.

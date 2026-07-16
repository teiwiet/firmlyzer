# 🔍 Firmware Analyzer & Fuzzer

A **Rust** CLI tool for embedded / IoT firmware security research.
The pipeline has three stages: **unpack firmware → hunt for secrets & analyze ELF binaries → fuzz the most promising target(polishing this stage)**.

---

## Features

- **Automatic firmware extraction** via `binwalk`.
- **Secret hunting**: sensitive files (`passwd`, `shadow`, `.key`, `.pem`, `.crt`, `dropbear`…) plus hardcoded private keys / passwords found inside file contents.
- **ELF analysis**: detects architecture (x86, x86_64, MIPS, MIPSEL, ARM32, ARM64), lists **dangerous functions** (`system`, `strcpy`, `sprintf`, `exec*`…) and **input functions** (`read`, `scanf`, `recv`, `getenv`…), then scores how interesting each binary is.
- **Mutation-based fuzzer**: feeds input over `stdin`, detects and saves crashes.
- **Parallel** directory scanning powered by `rayon`.

---

## Requirements

- **Rust** (stable) + Cargo
- **`binwalk`** available on your `PATH` (used for the extraction stage)

Crates used: `goblin`, `walkdir`, `serde`, `rayon`, `regex`, `rand`, `wait-timeout`.

---

## Build

```bash
cargo build --release
```

---

## Usage

The program exposes two main commands:

### 1. `analyze` — analyze firmware

```bash
cargo run --release -- analyze <firmware.bin> [report.json]
```

- Extracts `firmware.bin` → `_<firmware>.extracted/`
- Hunts for secrets in the extracted directory
- Analyzes every binary and sorts them by score (**descending**)
- Writes the result to a JSON file (defaults to `report.json`)

### 2. `fuzz` — fuzz a target

```bash
cargo run --release -- fuzz <report.json> [crash_dir] [max_iters]
```

- Reads the report and picks the **highest-scoring** target
- Mutates a seed and feeds the input to the target's `stdin`
- Saves crashes to `crash_dir` (defaults to `crashes/`); `max_iters` defaults to `100000`

---

## Scoring

```
score = num_dangerous_funcs + num_input_funcs × 2
```

Binaries containing none of these functions are skipped. Input functions are weighted double because they are usually where external data enters the program.

---

## Mutation strategies

`bit flip` · `byte flip` · `append` (random bytes) · `truncate` · `repeat` (duplicate a slice) · `insert_known` (inject canned payloads: path traversal, command injection, format strings, buffer-overflow strings…).

---

## Crash detection

An exit is treated as a "real" crash when the code is:

| Code | Meaning |
|------|---------|
| `139` | SIGSEGV (segfault) |
| `134` | SIGABRT (abort) |
| `-1`  | killed by a signal / spawn failure |

Crashing inputs are saved and **added back into the corpus** so they keep getting mutated in later iterations.

---

## Output

- **`report.json`** — list of binaries with their scores, architecture, and detected functions
- **`crashes/`** — inputs that made the target crash

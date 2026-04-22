# EvidenceChain

**Autonomous forensic investigation agent with self-correction for SANS SIFT Workstation**

EvidenceChain is a custom MCP server that exposes 21 typed forensic tools for autonomous incident response. An AI agent connects via stdio transport and uses these tools to investigate disk images and memory captures, with a built-in 4-pass self-correction engine that detects overclaims, catches contradictions, scores confidence, and plans reinvestigation -- all without human intervention.

Built for the [SANS Find Evil! Hackathon](https://findevil.devpost.com/) (April-June 2026).

## Architecture

```
+------------------+        stdio/MCP         +--------------------+
|                  | <======================> |                    |
|   AI Agent       |    21 typed tools        |  EvidenceChain     |
|   (Qoder /       |    JSON responses        |  MCP Server        |
|    Claude Code)  |                          |                    |
|                  |                          +--------+-----------+
+------------------+                                   |
                                                       |
                    +----------------------------------+----------------------------------+
                    |                  |                |                |                 |
              +-----+------+   +------+------+   +-----+------+  +-----+-----+   +------+------+
              |  9 Disk    |   |  6 Memory   |   | 4 Enrich   |  |  Correct  |   |  Report     |
              |  Tools     |   |  Tools      |   | Tools      |  |  Engine   |   |  Generator  |
              +-----+------+   +------+------+   +-----+------+  +-----+-----+   +------+------+
                    |                  |                |                |                 |
              +-----+------+   +------+------+   +-----+------+  +-----+-----+   +------+------+
              | Sleuth Kit |   | Volatility 3|   | VirusTotal |  | 7 Detectors|  | Jinja2      |
              | EZ Tools   |   | (pslist,    |   | AbuseIPDB  |  | Confidence |  | Templates   |
              | log2timeline|  |  psscan,    |   | MalwareBaz |  | Scorer     |  | MITRE KB    |
              | RegRipper  |   |  malfind,   |   | LOLBAS     |  | Reinvest.  |  | Narratives  |
              |            |   |  netscan)   |   | AlienVault |  | Planner    |  |             |
              +------------+   +-------------+   +------------+  +-----------+   +-------------+
                                                                       |
                                                              +--------+--------+
                                                              |  Evidence Store  |
                                                              |  Audit Logger    |
                                                              |  (JSONL)         |
                                                              +-----------------+
```

### Security Boundaries (Architectural, Not Prompt-Based)

| Boundary | Enforcement |
|---|---|
| Read-only evidence | `mount -o ro,loop,noatime` in code |
| Path allowlists | `PathValidator` checks every read/write path |
| Command denylist | `CommandGuard` blocks `rm`, `dd`, `curl`, `ssh`, `python`, etc. |
| Output cap | `OutputCap` truncates at 100KB per tool response |
| No shell access | Tools are typed MCP functions, no `execute_shell_cmd` |
| Write isolation | Only `analysis/`, `reports/`, `audit/` directories writable |

## Tools (21 total)

### Disk Analysis (9)
| Tool | What it does | Proves |
|---|---|---|
| `mount_evidence` | Mount E01/dd/raw read-only | -- |
| `get_filesystem_timeline` | MAC timeline via fls+mactime | File timestamps |
| `parse_mft` | MFTECmd with $SI vs $FN comparison | Timestomping detection |
| `parse_event_logs` | EvtxECmd with Event ID filtering | Security events |
| `parse_prefetch` | PECmd execution timestamps | **EXECUTION** (up to 8 runs) |
| `parse_amcache` | AmcacheParser with SHA1 | **EXECUTION** + hash |
| `parse_registry` | RECmd persistence/config | Persistence configured |
| `extract_file` | Pull file + SHA-256 | File contents |
| `unmount_evidence` | Clean teardown | -- |

### Memory Analysis (6)
| Tool | What it does | Proves |
|---|---|---|
| `memory_process_list` | pslist + psscan dual-scan | Running/hidden processes |
| `memory_network_connections` | netscan + netstat | Network connections |
| `memory_injected_code` | malfind (RWX regions) | **Suggests** injection |
| `memory_services` | svcscan | Service configuration |
| `memory_command_lines` | cmdline extraction | Command arguments |
| `memory_dump_process` | Process memory + strings | Deep analysis |

### Enrichment (4)
| Tool | What it does | Source |
|---|---|---|
| `compute_hashes` | MD5/SHA1/SHA256 | Local |
| `enrich_indicators` | Threat intel lookup | VT, AbuseIPDB, MalwareBazaar, LOLBAS, OTX |
| `yara_scan` | Pattern matching | YARA rules |
| `generate_super_timeline` | log2timeline + psort | Plaso |

### Self-Correction & Reporting (2)
| Tool | What it does |
|---|---|
| `run_self_correction` | 4-pass engine: validation, contradiction detection, confidence scoring, reinvestigation planning |
| `generate_report` | Markdown + JSON report with findings, MITRE coverage, timeline, audit trail |

## Self-Correction Engine

The engine runs 4 passes after each batch of tool executions:

1. **Inline Validation Summary** -- Aggregates overclaim flags and timestomping detections from tool validators
2. **Cross-Source Contradiction Detection** -- 7 detectors find internal inconsistencies:
   - `TIMESTAMP_PARADOX` -- Cross-artifact timestamp conflicts
   - `EXECUTION_OVERCLAIM` -- Claims execution from presence-only evidence (CRITICAL)
   - `GHOST_PROCESS` -- Memory process with no disk trace
   - `TIMELINE_GAP` -- Suspicious event log gaps (>6h with clearing correlation)
   - `ATTRIBUTION_MISMATCH` -- Hash conflicts across sources
   - `ANTI_FORENSIC_INDICATOR` -- Timestomping, log clearing, known tools
   - `PHANTOM_ARTIFACT` -- Hallucination catcher (CRITICAL)
3. **Confidence Scoring** -- Evidence-weighted 0.0-1.0 scores:
   - DIRECT evidence (0.90) > CORROBORATED (0.80) > CIRCUMSTANTIAL (0.50) > INFERRED (0.30)
   - Auto-confirms findings >= 0.75, flags for review < 0.40
   - Semantic implication: EXECUTION implies PRESENCE
4. **Reinvestigation Planning** -- Prioritized tool calls to resolve unresolved contradictions

The pipeline iterates up to 3 times or until convergence (zero new contradictions).

## Setup

### Prerequisites
- Python 3.10+
- SANS SIFT Workstation (for full tool access)

### Quick Install (SIFT VM)

```bash
git clone <repo-url> evidencechain
cd evidencechain
bash install.sh
```

The installer will:
- Create a virtual environment
- Install dependencies
- Check for SIFT forensic tools
- Run smoke tests
- Print MCP configuration

### Manual Install

```bash
git clone <repo-url> evidencechain
cd evidencechain
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### MCP Configuration

Add to your agent's MCP config:

```json
{
  "mcpServers": {
    "evidencechain": {
      "command": "/path/to/evidencechain/.venv/bin/python3",
      "args": ["-m", "evidencechain"],
      "cwd": "/path/to/evidencechain/src",
      "env": {
        "EVIDENCE_BASE_DIR": "/cases",
        "VT_API_KEY": "your-key-here",
        "ABUSEIPDB_API_KEY": "your-key-here",
        "OTX_API_KEY": "your-key-here"
      }
    }
  }
}
```

Threat intel API keys are optional. LOLBAS and MalwareBazaar work without keys.

## Try It Out (Judges)

1. **Download the SIFT Workstation** from sans.org/tools/sift-workstation
2. **Install Protocol SIFT**: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
3. **Clone and install EvidenceChain**: `git clone <repo-url> && cd evidencechain && bash install.sh`
4. **Place evidence** in `/cases/` (disk images, memory captures)
5. **Configure your agent** with the MCP config from the installer output
6. **Start the agent** -- it will autonomously analyze the evidence

The agent will:
- Mount and parse disk artifacts
- Analyze memory for hidden processes and injected code
- Enrich indicators via threat intelligence
- Self-correct by detecting contradictions and re-investigating
- Generate a structured Markdown + JSON report

## Running Tests

```bash
# All smoke tests
python3 tests/test_block2_smoke.py   # 10 tests — disk tools + validators
python3 tests/test_block3_smoke.py   # 12 tests — memory tools + validators
python3 tests/test_block4_smoke.py   # 55 tests — self-correction engine
python3 tests/test_block5_smoke.py   # 66 tests — threat intel enrichment
python3 tests/test_block6_smoke.py   # 74 tests — report generator
python3 tests/test_block7_integration.py  # integration tests

# Full regression
python3 -c "
import subprocess, sys
for t in ['tests/test_block2_smoke.py','tests/test_block3_smoke.py',
          'tests/test_block4_smoke.py','tests/test_block5_smoke.py',
          'tests/test_block6_smoke.py','tests/test_block7_integration.py']:
    r = subprocess.run([sys.executable, t], capture_output=True, text=True)
    print(f'{t}: {\"PASS\" if r.returncode == 0 else \"FAIL\"}')"
```

## Project Structure

```
evidencechain/
  src/evidencechain/
    server.py              # MCP server entry point (21 tools)
    enums.py               # 12 enums (ArtifactType, EvidenceSemantics, etc.)
    models.py              # 11 dataclasses (EvidenceAtom, ForensicFinding, etc.)
    config.py              # Configuration + security constants
    forensic_semantics.py  # What each artifact PROVES vs CANNOT_PROVE
    security/
      path_validator.py    # Read/write path allowlists
      command_guard.py     # Binary denylist
      output_cap.py        # 100KB output truncation
    provenance/
      evidence_store.py    # Central atom/finding/contradiction store
      audit_logger.py      # Append-only JSONL audit trail
      evidence_registry.py # Tool execution tracking
    tools/
      base.py              # Base tool executor
      disk.py              # 9 disk analysis tools
      memory.py            # 6 memory analysis tools
      enrichment.py        # 4 enrichment tools
    validators/
      base.py              # Base validator
      timestamps.py        # Cross-timestamp validation
      shimcache.py         # ShimCache semantics (PRESENCE only)
      prefetch.py          # Prefetch execution proof
      amcache.py           # Amcache execution + hash
      mft.py               # MFT timestomping detection
      evtx.py              # Event log validation
      registry.py          # Registry persistence validation
      memory.py            # Memory artifact validation
    correction/
      detectors.py         # 7 contradiction detectors
      confidence.py        # Evidence-weighted confidence scoring
      engine.py            # 4-pass correction orchestrator
    threat_intel/
      rate_limiter.py      # Token bucket per-source limiter
      aggregator.py        # Weighted consensus verdict
      sources/
        base.py            # Abstract source adapter
        virustotal.py      # VirusTotal API v3
        abuseipdb.py       # AbuseIPDB v2
        malwarebazaar.py   # MalwareBazaar (free, no key)
        lolbas.py          # 25 LOLBins knowledge base
        alienvault_otx.py  # AlienVault OTX v1
    knowledge/
      forensic_kb.py       # MITRE ATT&CK (30+), baselines, narratives
    report/
      builder.py           # ReportData assembly from evidence store
      generator.py         # Jinja2 rendering to Markdown + JSON
      templates/
        report.md.j2       # Markdown report template
        report.json.j2     # JSON report template
  tests/
    test_block2_smoke.py   # Disk tools tests
    test_block3_smoke.py   # Memory tools tests
    test_block4_smoke.py   # Self-correction tests
    test_block5_smoke.py   # Threat intel tests
    test_block6_smoke.py   # Report generator tests
    test_block7_integration.py  # Full pipeline integration
  AGENTS.md                # Agent configuration guide
  install.sh               # One-command installer
  pyproject.toml           # Package metadata
  LICENSE                  # MIT
```

## Audit Trail

Every tool execution is logged to `analysis/audit/` as append-only JSONL:
- `executions.jsonl` -- Tool calls with arguments, duration, results
- `findings.jsonl` -- Finding creation and status changes
- `contradictions.jsonl` -- Detected contradictions with affected findings
- `corrections.jsonl` -- Self-correction iterations and convergence

Judges can trace any finding back to the exact tool execution that produced it via `execution_id` linkage through `EvidenceAtom` records.

## License

MIT -- see [LICENSE](LICENSE).

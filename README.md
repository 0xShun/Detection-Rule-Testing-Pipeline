# Detection Rule Testing Pipeline

A structured framework for validating, testing, and managing **Sigma-compatible detection rules** against realistic log data. This project provides a repeatable pipeline for security engineers and detection teams to verify that detection rules correctly identify malicious activity — and produce a machine-readable test report appended directly to each rule file.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Detection Rules](#detection-rules)
- [Log Data](#log-data)
- [Test Reports (Tested Rules)](#test-reports-tested-rules)
- [Pipeline Workflow](#pipeline-workflow)
- [Rule Format Reference](#rule-format-reference)
- [Test Report Schema](#test-report-schema)
- [Log Format Reference](#log-format-reference)
- [Coverage Matrix](#coverage-matrix)
- [Extending the Pipeline](#extending-the-pipeline)

---

## Overview

Detection engineers write rules, but without a disciplined testing process, there is no guarantee a rule will fire on real attack telemetry. This pipeline solves that by:

1. Storing detection rules in standard Sigma YAML format under `rules/`
2. Providing curated, realistic log samples under `logs/` that simulate both attacker activity and benign noise
3. Running each rule against its matching log category and recording results in a `tested-rules/` output — a copy of the original rule file annotated with an `x-test-report` block

This approach keeps rules self-documenting: a rule file in `tested-rules/` tells you not only *what* it detects, but *whether it was verified* and *against which log entries*.

---

## Project Structure

```
Detection-Rule-Testing-Pipeline/
│
├── rules/                          # Source detection rules (Sigma YAML)
│   ├── detect_mimikatz_cmdline.yml
│   ├── suspicious_powershell_encoded.yml
│   ├── sample_powershell_encoded.yml
│   ├── okta_user_account_locked_out.yml
│   ├── test_rule.yml
│   ├── New_test.yml
│   └── sample.yml
│
├── logs/                           # Simulated log data for rule testing
│   ├── windows/
│   │   ├── process_creation/
│   │   │   ├── mimikatz_exec.json      # Mimikatz credential dump
│   │   │   ├── lsass_dump.json         # LSASS memory access + ProcDump
│   │   │   └── psexec_lateral.json     # PsExec lateral movement
│   │   ├── network_connection/
│   │   │   ├── c2_beacon.json          # C2 beaconing via svchost32.exe
│   │   │   └── port_scan.json          # Nmap port scan activity
│   │   ├── process_creation.json       # Generic process creation log
│   │   └── test.json
│   ├── linux/
│   │   └── test_linux.json
│   ├── network/
│   │   └── test_network.json
│   ├── web/
│   │   └── test.log
│   └── raw/
│       ├── Apache.log
│       └── test.log
│
└── tested-rules/                   # Rule files annotated with test results
    ├── de__detect_mimikatz_cmdline.yml
    ├── sample_successful.yml
    └── de__unknown.yml
```

---

## Detection Rules

Rules are written in **Sigma format** — a vendor-agnostic YAML standard for describing detection logic. Each rule specifies a log source, detection conditions, and metadata including MITRE ATT&CK mappings.

### Available Rules

| File | Title | Log Source | Level | MITRE Technique |
|------|-------|-----------|-------|-----------------|
| `detect_mimikatz_cmdline.yml` | Mimikatz Execution via Command Line | Windows / process_creation | Critical | T1003.001 |
| `suspicious_powershell_encoded.yml` | Suspicious PowerShell Encoded Command Execution | Windows / process_creation | Medium | T1059.001, T1027 |
| `sample_powershell_encoded.yml` | Suspicious PowerShell Encoded Command Execution | Windows / process_creation | Medium | T1059.001 |
| `okta_user_account_locked_out.yml` | Okta User Account Locked Out | Okta / okta | Medium | Impact |
| `test_rule.yml` | Test Detection Rule | Windows / process_creation | — | — |
| `New_test.yml` | Test Rule | Windows / process_creation | — | — |
| `sample.yml` | Test Rule | Windows / process_creation | — | — |

### Rule Detail: Mimikatz Execution via Command Line

This is the most complete and verified rule in the project. It detects Mimikatz usage by matching known command-line arguments:

```yaml
title: Mimikatz Execution via Command Line
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects execution of Mimikatz based on known command line arguments.
author: Shun
date: 2026/03/16
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'privilege::debug'
  condition: selection
falsepositives:
  - Authorized red team operations
level: critical
```

**Detection logic:** Fires on any Windows process creation event where the `CommandLine` field contains either `sekurlsa::logonpasswords` or `privilege::debug` — both canonical Mimikatz invocations.

### Rule Detail: Suspicious PowerShell Encoded Command

Detects obfuscated PowerShell execution via encoded command-line flags, a common defense evasion technique:

```yaml
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-e '
  condition: selection
```

**Detection logic:** Matches PowerShell processes (`powershell.exe` or `pwsh.exe`) launched with encoded command arguments. Both variants (`suspicious_powershell_encoded.yml` and `sample_powershell_encoded.yml`) cover this technique with slightly different field lists.

### Rule Detail: Okta User Account Locked Out

A cloud-focused rule targeting Okta system logs:

```yaml
logsource:
  product: okta
  service: okta
detection:
  selection:
    displaymessage: Max sign in attempts exceeded
  condition: selection
```

**Detection logic:** Fires when an Okta log entry carries the `displaymessage` value `Max sign in attempts exceeded`, indicating brute-force or credential stuffing attempts.

---

## Log Data

Log files simulate realistic Sysmon-formatted Windows telemetry (EventIDs following the Sysmon schema) alongside Linux and network logs. All log files are JSON arrays of event objects unless otherwise noted.

### Windows Logs

#### `process_creation/mimikatz_exec.json`
Two Sysmon EventID 1 (process creation) events. The first simulates direct Mimikatz execution:
- **Image:** `C:\Users\victim\Downloads\mimikatz.exe`
- **CommandLine:** `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
- **IntegrityLevel:** High
- **User:** `LAB\victim`

The second event is benign (Notepad opening a text file) — included as a **true negative** to validate the rule does not over-fire.

#### `process_creation/lsass_dump.json`
Two events targeting LSASS:
- **Event 1 — Sysmon EventID 10 (process access):** `mimikatz.exe` accessing `lsass.exe` with `GrantedAccess: 0x1010`
- **Event 2 — Sysmon EventID 1:** `procdump.exe -ma lsass.exe lsass.dmp` — a common LSASS dump technique using Sysinternals ProcDump

#### `process_creation/psexec_lateral.json`
Two events simulating lateral movement via PsExec:
- **Event 1:** `PsExec.exe \\192.168.1.50 -u Administrator -p Password123 cmd.exe` — explicit credential passing over the network, run as `LAB\attacker`
- **Event 2:** `cmd.exe /Q /c whoami` spawned as `NT AUTHORITY\SYSTEM` by PsExec — confirming successful privilege escalation on the remote host

#### `network_connection/c2_beacon.json`
Two Sysmon EventID 3 (network connection) events:
- **Image:** `C:\Users\victim\AppData\Roaming\svchost32.exe` — a suspicious masquerading executable
- **Destination:** `185.220.101.47:443` — an external IP with HTTPS traffic at regular 5-minute intervals (classic C2 beacon pattern)

#### `network_connection/port_scan.json`
Three rapid Sysmon EventID 3 events within 2 seconds:
- **Image:** `C:\Tools\nmap.exe`
- **User:** `LAB\attacker`
- **Targets:** Ports 22, 80, 443 on `192.168.1.1` in sequence

#### `windows/process_creation.json` / `windows/test.json`
Generic test fixtures for process creation and Windows log structure validation.

### Linux & Network Logs

| File | Description |
|------|-------------|
| `logs/linux/test_linux.json` | Placeholder Linux event log for rule testing against Linux logsources |
| `logs/network/test_network.json` | Placeholder network event log |
| `logs/web/test.log` | Raw web server log (for web-category rules) |
| `logs/raw/Apache.log` | Apache access log for raw log parsing tests |
| `logs/raw/test.log` | Generic raw log for parser development |

---

## Test Reports (Tested Rules)

After a rule is tested against its log data, an `x-test-report` block is appended to a copy of the rule file, which is saved in `tested-rules/`. This output preserves the original rule while adding structured verification metadata.

### `tested-rules/de__detect_mimikatz_cmdline.yml`

This is the most complete test output in the project, showing a fully verified, high-confidence rule:

```yaml
x-test-report:
  rule_source: de
  tested_at: 2026-03-17T01:19:33.239Z
  log_type: windows/process_creation
  syntax_pass: true
  syntax_errors: []
  log_files_tested: 3
  log_entries_tested: 6
  match_count: 6
  matched: true
  matched_entries:
    - file: lsass_dump.json
      entry_index: 0
    - file: lsass_dump.json
      entry_index: 1
    - file: mimikatz_exec.json
      entry_index: 0
    - file: mimikatz_exec.json
      entry_index: 1
    - file: psexec_lateral.json
      entry_index: 0
    - file: psexec_lateral.json
      entry_index: 1
  noise_level: Unknown
  noisy_conditions: []
  tuning_suggestions: []
```

**Interpretation:** The rule passed syntax validation with no errors. It was tested against 3 log files containing 6 total entries, and matched all 6. Every simulated attack scenario in the log set triggered the rule. No false positives were flagged.

### `tested-rules/de__unknown.yml`

An early-stage or placeholder test report with no matched entries and a fidelity score of 0 — representing a rule that has not yet been verified against real log data:

```yaml
x-test-report:
  rule_source: unknown
  tested_at: 2026-03-05T03:17:17.680Z
  syntax_pass: null
  fidelity_score: 0
  true_positive_likely: false
  noise_level: Unknown
```

### `tested-rules/sample_successful.yml`

A minimal passing test record — the rule body is absent (stripped or placeholder), but the `x-test-report` block structure demonstrates the schema used for successful rule outputs.

---

## Pipeline Workflow

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  rules/     │────▶│  Syntax Check    │────▶│  Log Matching    │────▶│  tested-rules/       │
│  *.yml      │     │  (YAML + Sigma   │     │  (run rule       │     │  rule + x-test-report│
│             │     │   schema valid.) │     │   against logs/) │     │  appended            │
└─────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────────┘
                                                      ▲
                                               ┌──────┴──────┐
                                               │   logs/     │
                                               │  *.json     │
                                               │  *.log      │
                                               └─────────────┘
```

### Step-by-Step

1. **Author a rule** in `rules/` using Sigma YAML format. Define `logsource.category` and `logsource.product` to identify which log directory to test against.

2. **Select matching logs** from `logs/<product>/<category>/`. The pipeline maps the rule's `logsource` to the corresponding log directory — e.g., a rule with `product: windows` and `category: process_creation` tests against `logs/windows/process_creation/*.json`.

3. **Syntax validation** checks that the YAML is well-formed and the `detection` block follows Sigma field modifier conventions (`|contains`, `|endswith`, etc.).

4. **Log matching** evaluates each log entry against the rule's `detection.selection` conditions. Matches are recorded by filename and entry index.

5. **Test report generation** appends an `x-test-report` block to the rule and writes the result to `tested-rules/`, prefixed with `de__` (or another source tag) to distinguish output from source files.

6. **Review results.** Rules with `matched: false` need investigation — either the detection logic is wrong, or the log fixtures don't include the expected attack pattern. Rules with very high `match_count` relative to total entries may be noisy.

---

## Rule Format Reference

Rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma). Key fields:

| Field | Required | Description |
|-------|----------|-------------|
| `title` | Yes | Human-readable rule name |
| `id` | Recommended | UUID identifying the rule |
| `status` | Yes | `stable`, `test`, or `experimental` |
| `description` | Yes | What the rule detects and why |
| `author` | Recommended | Rule author |
| `date` | Recommended | Creation date (YYYY/MM/DD) |
| `tags` | Recommended | MITRE ATT&CK tags (e.g., `attack.t1003.001`) |
| `logsource.category` | Yes | Log category (e.g., `process_creation`) |
| `logsource.product` | Yes | Platform (e.g., `windows`, `okta`) |
| `detection.selection` | Yes | Field-value conditions |
| `detection.condition` | Yes | Boolean logic over selections |
| `falsepositives` | Recommended | Known benign scenarios |
| `level` | Recommended | `informational`, `low`, `medium`, `high`, `critical` |

### Supported Field Modifiers

| Modifier | Meaning | Example |
|----------|---------|---------|
| `\|contains` | Field contains substring | `CommandLine\|contains: 'sekurlsa'` |
| `\|endswith` | Field ends with value | `Image\|endswith: '\powershell.exe'` |
| `\|startswith` | Field starts with value | `Image\|startswith: 'C:\Users'` |
| *(none)* | Exact match or glob | `Image: '*\cmd.exe'` |

---

## Test Report Schema

The `x-test-report` block is a custom Sigma extension appended by the pipeline engine.

| Field | Type | Description |
|-------|------|-------------|
| `rule_source` | string | Origin tag of the rule (e.g., `de`, `unknown`) |
| `tested_at` | ISO 8601 | Timestamp of the test run |
| `log_type` | string | Log path pattern tested (e.g., `windows/process_creation`) |
| `syntax_pass` | boolean / null | Whether the rule passed YAML and Sigma syntax checks |
| `syntax_errors` | array | List of syntax error messages (empty if none) |
| `log_files_tested` | integer | Number of log files evaluated |
| `log_entries_tested` | integer | Total log entries across all tested files |
| `match_count` | integer | Number of entries that triggered the rule |
| `matched` | boolean | Whether at least one match was found |
| `matched_entries` | array | List of `{file, entry_index}` objects for each match |
| `noise_level` | string | Qualitative noise assessment (`Unknown`, `Low`, `Medium`, `High`) |
| `noisy_conditions` | array | Specific conditions assessed as overly broad |
| `tuning_suggestions` | array | Recommended refinements to reduce false positives |
| `fidelity_score` | integer | (Legacy) 0–100 score for rule confidence |
| `true_positive_likely` | boolean | (Legacy) Whether a true positive is expected |

---

## Log Format Reference

Windows log files use the Sysmon event schema. Key EventIDs used in this project:

| EventID | Category | Description |
|---------|----------|-------------|
| 1 | process_creation | A new process was created |
| 3 | network_connection | A network connection was made |
| 10 | process_access | A process opened another process (e.g., LSASS access) |

### Common Fields (EventID 1 — Process Creation)

| Field | Description | Example |
|-------|-------------|---------|
| `EventID` | Sysmon event type | `1` |
| `Computer` | Hostname | `DESKTOP-LAB01` |
| `UtcTime` | Event timestamp | `2026-03-16 06:00:01.000` |
| `Image` | Full path of process | `C:\Users\victim\Downloads\mimikatz.exe` |
| `CommandLine` | Full command including arguments | `mimikatz.exe "privilege::debug"` |
| `User` | Executing user | `LAB\victim` |
| `IntegrityLevel` | Process integrity | `High`, `Medium`, `System` |
| `ParentImage` | Parent process path | `C:\Windows\System32\cmd.exe` |
| `Hashes` | SHA256 hash of the executable | `SHA256=92D1...` |

---

## Coverage Matrix

This matrix maps each rule to its tested log scenarios and shows whether a match was confirmed.

| Rule | Log File(s) Tested | Match Confirmed | Notes |
|------|--------------------|-----------------|-------|
| `detect_mimikatz_cmdline` | `mimikatz_exec.json`, `lsass_dump.json`, `psexec_lateral.json` | ✅ Yes (6/6) | All entries matched |
| `suspicious_powershell_encoded` | *(not yet in tested-rules)* | ❓ Pending | No test report generated |
| `sample_powershell_encoded` | *(not yet in tested-rules)* | ❓ Pending | No test report generated |
| `okta_user_account_locked_out` | *(no Okta logs present)* | ❓ Pending | Needs Okta log fixtures |
| `test_rule` / `New_test.yml` | *(not yet in tested-rules)* | ❓ Pending | Development stubs |
| `sample.yml` | `de__unknown.yml` (partial) | ❌ No match | Fidelity score 0; needs log fixture |

---

## Extending the Pipeline

### Adding a New Rule

1. Create a `.yml` file in `rules/` following the Sigma format.
2. Set `logsource.category` and `logsource.product` to match an existing log directory, or add a new log directory under `logs/`.
3. Run the pipeline against the new rule to generate a test report in `tested-rules/`.

### Adding New Log Fixtures

Place log files under `logs/<product>/<category>/`. File format should be a JSON array of event objects. To validate a rule produces **no false positives**, include benign events alongside attack events in the same fixture (as done in `mimikatz_exec.json`, which includes a harmless Notepad event).

### Adding a New Log Category

Create a new subdirectory under `logs/` (e.g., `logs/linux/auth/`) and populate it with representative JSON log entries. Update any rule whose `logsource.category` matches the new category to reference the new path.

### Naming Conventions

| Artifact | Convention | Example |
|----------|-----------|---------|
| Rule files | `snake_case.yml` | `detect_mimikatz_cmdline.yml` |
| Log files | descriptive attack name | `lsass_dump.json`, `c2_beacon.json` |
| Tested rule output | `<source>__<rule_name>.yml` | `de__detect_mimikatz_cmdline.yml` |

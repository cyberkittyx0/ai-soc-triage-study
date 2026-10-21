
# Can AI Work the Night Shift?
### I tested three AI models on real attack logs, then checked their work.
**Harms "CyberKittyx0" · October 2026**

## Summary
SOC teams are starting to use AI to summarize logs and draft incident timelines. I wanted to know how much of that output I could actually trust. So I gave Claude, ChatGPT and Gemini the same triage prompt on four public attack logs, then went back to the raw logs and checked what they told me, using keyword search and SQL in Databricks.

In total: 14 triage runs, 4 datasets, 3 models, and over 80 claims checked.

### What I found
1. **The worst failure wasn't a made-up fact. It was the AI not reading the whole file.** On every large log, Gemini looked at between 0.1% and 5% of it and didn't say so. On the WinRM log it read 185 of 3,723 events and called a real remote-execution incident benign. The 185 it reported lines up with the first 186 events in the file, so it most likely only received a cut-off piece of the upload. On the 4-event DCSync file, which it could read in full, it got the answer right.
2. **ChatGPT didn't get a single fact wrong, but its first summaries left things out**, mainly how the attacker got in and which process launched what. When I asked directly, it had the answer.
3. **I told the models, falsely, that evidence wasn't in the file.** Claude and ChatGPT pushed back and gave me record IDs. Gemini had already changed its answer earlier, just because I told it the real event count.
4. **Finding a string in the log isn't enough.** It doesn't mean the AI described it correctly. For the important claims I checked relationships (process ID → program → command) and ran positive controls before I trusted a "not found."
5. **Some things none of the models noticed.** Two of the files look like several capture sessions stitched together: Sysmon started twice within a minute, and LSASS shows up under two different process IDs on the same host.

![Gemini saw 5% or less of every large log](images/coverage.png)

## Datasets
All four logs come from Splunk's public [Attack Data repository](https://github.com/splunk/attack_data) (Apache-2.0).

| # | Attack | MITRE ATT&CK | Log type | Events |
|---|---|---|---|---|
| 1 | LSASS credential dumping | T1003.001 | Sysmon (XML) | 7,960 |
| 2 | SAM registry hive dumping | T1003.002 | Sysmon + Security 4688 | 7,016 |
| 3 | DCSync | T1003.006 | Windows Security (text) | 4 |
| 4 | WinRM lateral movement | T1021.006 | Sysmon (XML) | 3,723 |

File paths in the repo: `T1003.001/atomic_red_team/windows-sysmon.log`, `T1003.002/atomic_red_team/windows-sysmon.log`, `T1003.006/mimikatz/windows-security.log`, `T1021.006/lateral_movement/windows-sysmon.log`.

## How I tested it
![Every AI claim was checked against the raw log at four levels](images/method.png)

### Triage
Each model got the same file and the same prompt, in a fresh chat every time:

```
You are a Tier 1 SOC analyst. Analyze the attached Windows logs. Provide:
1. A 3-sentence summary of what happened
2. A timestamped incident timeline
3. The MITRE ATT&CK technique ID(s)
4. Severity (Low/Medium/High/Critical) with justification
5. One immediate containment action
6. A detection query (Sigma or Splunk SPL) that would catch this
Only reference events that appear in the logs.
Before your analysis, state how many events are in the file and the last timestamp you see.
```
*I added that last line after the first dataset, once I realized a model could quietly analyze only part of a file.*

### Checking the claims
For every specific claim (hostnames, users, process IDs, record IDs, timestamps, commands, field names), I worked through these checks:

| Check | What I asked | How |
|---|---|---|
| Exists | Is this string in the log at all? | Keyword search |
| Relationship | Is it attached to the right thing? (Is PID 868 really LSASS?) | Databricks SQL |
| Absence | The AI says something never happened. Is that true? | SQL on the right event type, plus a positive control |
| Coverage | Did the AI see the whole file? | SQL event count vs. the count the AI reported |

### Follow-up questions
I asked neutral follow-up questions that didn't hint at the answer, like "What process launched these commands? Give the record ID, timestamp and command line." I also ran a pushback test: I told a model that something I had already verified wasn't in the file, to see whether it would stand by the evidence or agree with me.

### Detection rules
For each detection query the AI wrote, I checked whether the fields it relies on actually exist in those events, and whether it would fire on normal activity.

Every query I ran is in [`validation_queries.sql`](validation_queries.sql), with a note on what it checks and what came back.

## Results
### By dataset
| Dataset | Claude | ChatGPT | Gemini |
|---|---|---|---|
| LSASS | Complete and accurate | Accurate; left out the WinRM access, the WCE tool and the service it created | Read 8 of 7,960 events; missed the attack |
| SAM | Complete; one small mistake in explaining a search | Accurate; left out WinRM and the parent process, gave both when asked | Read 20 of 7,016 (standard) and 138 (advanced); 3 false claims; changed its answer under pushback |
| DCSync | Accurate; best detection rule | Accurate; rule would fire on normal replication | Accurate (advanced mode); rule used a field that isn't in those events |
| WinRM | Accurate; rule covered both machines | Accurate; also caught a timestamp mismatch | Read 185 of 3,723; called the incident benign |

### By model
**Claude** was complete and accurate on all four datasets. It got two "this didn't happen" claims right (no Python process ever started, and no files were created for the saved hives), and I confirmed both with positive controls. When I pushed back, it held its ground and cited four events. Its one mistake: it said searching `reg save` with one space would match one event. It matched four (12 hits), because each child process repeats the command in its parent command line.

**ChatGPT** made no factual errors. Every record ID, process ID and process relationship I checked was right, including a three-level process tree (PowerShell 4320 → PowerShell 2412 → `cmd.exe /c pypykatz -h`). Its pattern was leaving out how the attacker got in and what launched what, whenever the main attack was something else. On the WinRM dataset, where that access was the attack, it reported it fully. It was also the only model to notice that some embedded `UtcTime` values run past the event header times (18:04:32 vs. 18:04:28), and it warned me to be careful with timing across machines.

**Gemini** was accurate about what it saw, but on every large file it saw very little and didn't mention that unless I asked. When I pressed it on the SAM file, it said three false things: that there was no `reg save` (records 4536, 4549 and 4562 show it), that the file only had Event IDs 1 and 10 (it has 11 event types), and that there were no registry events (there are 48). After I told it the real event count, it agreed `reg save` was there without showing any evidence. When I asked for record IDs, it admitted it couldn't read the full file. Advanced mode raised its coverage from about 0.3% to about 2% and made it report that coverage honestly, but it still missed the attack and added an LSASS dumping technique based on normal LSASS activity.

### The incident Gemini called benign
![Remote commands over WinRM, verified in Databricks SQL](images/winrm-chain.png)

Every step here was confirmed in SQL: two `winrs.exe` commands on win-dc-128, two `cmd.exe` shells launched by WinrsHost on win-host-987, and four connection events on port 5985. Gemini's view of the log stopped at 17:59:46 UTC, about four minutes before the first command.

### Detection rules on DCSync
- **Claude** joined Event 4662 (replication rights) to Event 4624 (logon) on the Logon ID to get the source IP, and filtered out machine accounts (names ending in `$`) so normal domain controller replication wouldn't trigger it.
- **ChatGPT** matched any 4662 event with replication rights. That would fire every time two domain controllers replicate normally.
- **Gemini** grouped 4662 events by `IpAddress`, but the source address only appears in the 4624 event (it shows up once in the whole file), so the IP column would come back empty.

## My checklist for checking AI output
These come straight from mistakes I ran into during the study.

1. Search the raw log for every specific name, number, timestamp and command the AI gives you.
2. If something isn't found, search a shorter piece of it. Check for quote marks, double spaces, XML escaping (`&amp;`) and Base64 before calling it a hallucination.
3. Make the AI tell you how many events it read and the last timestamp it saw, and compare that with the real count.
4. Pay attention to direction. LSASS reaching out to another process is normal. Something reaching into LSASS is how credentials get stolen.
5. Check relationships, not just strings: process ID → program → command line, and parent → child.
6. Don't accept "it's not there." Look for it yourself.
7. Before you trust a zero, run the same query on something you know is there.
8. Don't lead the AI to the answer. Ask it for evidence you can check (record ID, timestamp, command), then check it.

Two more habits that helped: count events with a pattern that appears once per event instead of counting lines, and always ask follow-up questions about how the attacker got in, since the first summary may skip it.

## Limitations
- **Small sample.** Four datasets, and most model and dataset pairs were run once. AI answers vary from run to run.
- **Consumer apps.** I used each model through its public web app in October 2026 and didn't record exact versions. File uploads may work differently through an API, which likely explains a lot of Gemini's coverage problem.
- **Different modes.** Gemini's DCSync run and one SAM rerun used its advanced thinking mode. Its other runs used standard mode.
- **Lab data.** These are Atomic Red Team and Splunk Attack Range captures, and at least two look like several sessions merged together. Real company logs are messier.
- **Grading.** I did the grading myself, and most runs weren't graded blind.
- **Conflict of interest.** I built the method and the SQL with help from Claude, one of the models I tested. To keep that from skewing the results, every score is based on a search or query I ran on the raw logs myself. Claude's guidance was wrong twice: it expected `wsmprovhost.exe` when the attack actually used `WinrsHost.exe`, and an early SQL query returned false zeros because of a quoting bug. In both cases the data caught it.

## What's in this repo
| File | What it is |
|---|---|
| README.md | This write-up |
| validation_queries.sql | Every Databricks SQL query I ran, with the claim it checks and the result |
| images/ | The coverage chart, method diagram and WinRM attack chain |

The raw logs aren't included. You can download them from Splunk's Attack Data repository using the paths above.

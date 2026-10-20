-- =====================================================================
-- AI Triage Reliability Study: Validation Queries (Databricks SQL)
-- Author: Harmony Debowski
--
-- Purpose: verify claims made by three AI models (Claude, ChatGPT,
-- Gemini) about four public attack datasets (Splunk attack_data),
-- by querying the raw Sysmon / Windows Security logs directly.
--
-- Data: each log file was uploaded to a Databricks volume and loaded
-- as one row per line (column: value).
--
-- Notes on method:
--   * '_' is used as a single-character wildcard in LIKE patterns in
--     place of a quote mark. An earlier version that used '' to escape
--     quotes silently returned false zeros, so every pattern was
--     re-tested with a positive control.
--   * "Absence" claims (X never happened) were tested with event-type
--     filters plus a positive-control query proving the same query
--     can find comparable events.
--   * Event counts use a pattern that appears exactly once per event
--     ('<Event ' for Sysmon XML, 'LogName=' for Security text logs),
--     not raw line counts.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. Load tables
-- ---------------------------------------------------------------------
CREATE TABLE lsass_logs AS
SELECT * FROM read_files('/Volumes/workspace/default/logs/AI-Triage-Study/1-LSASS.txt', format => 'text');

CREATE TABLE sam_logs AS
SELECT * FROM read_files('/Volumes/workspace/default/logs/AI-Triage-Study/2-SAM.txt', format => 'text');

CREATE TABLE dcsync_logs AS
SELECT * FROM read_files('/Volumes/workspace/default/logs/AI-Triage-Study/3-DCSync.txt', format => 'text');

CREATE TABLE winrm_logs AS
SELECT * FROM read_files('/Volumes/workspace/default/logs/AI-Triage-Study/4-WinRM.txt', format => 'text');


-- =====================================================================
-- DATASET 1: LSASS credential dumping (T1003.001)
-- =====================================================================

-- True event count (Gemini reported 8). Result: 7,960 events.
-- (Raw line count was 7,974; 14 lines were not events.)
SELECT COUNT(*) FROM lsass_logs WHERE value LIKE '<Event %';

-- Sanity check: events where something accessed LSASS on win-dc-807.
-- Result: 151.
SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%win-dc-807%'
  AND value LIKE '%lsass.exe</Data><Data Name=_GrantedAccess%';

-- Claude claim: "PID 868 is LSASS" (comsvcs.dll MiniDump 868).
-- Result: 151 of 151 LSASS-target events have PID 868. VERIFIED.
SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%win-dc-807%'
  AND value LIKE '%lsass.exe</Data><Data Name=_GrantedAccess%'
  AND value LIKE '%TargetProcessId_>868<%';

-- Control: same query with PID 860. Result: 0.
SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%win-dc-807%'
  AND value LIKE '%lsass.exe</Data><Data Name=_GrantedAccess%'
  AND value LIKE '%TargetProcessId_>860<%';

-- ChatGPT claim: record 5392 = ProcDump on win-dc-807. Result: 1. VERIFIED.
SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%<EventRecordID>5392</EventRecordID>%'
  AND value LIKE '%win-dc-807%'
  AND lower(value) LIKE '%procdump%';

-- ChatGPT claim: record 5434 = lsass_dump.dmp created. Result: 1. VERIFIED.
SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%<EventRecordID>5434</EventRecordID>%'
  AND value LIKE '%win-dc-807%'
  AND value LIKE '%lsass_dump.dmp%';

-- Claude + ChatGPT claim: 37 remote threads created in LSASS. Result: 37. VERIFIED.
SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%<EventID>8</EventID>%'
  AND value LIKE '%644c305e%'
  AND value LIKE '%lsass.exe%';

-- Is ChatGPT's 0x1410 detection noisy? Which programs opened LSASS with 0x1410?
-- Result: powershell.exe, rundll32.exe, taskmgr.exe (1 each), all attack-related.
-- Not noisy in this dataset; untested against normal production traffic.
SELECT regexp_extract(value, 'SourceImage.>([^<]+)<', 1) AS source, COUNT(*) AS hits
FROM lsass_logs
WHERE value LIKE '%lsass.exe</Data><Data Name=_GrantedAccess_>0x1410<%'
GROUP BY 1 ORDER BY hits DESC;

-- Gemini claims: WinrsHost = PID 816, csc.exe = PID 4484. Results: 1 and 4. VERIFIED.
SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%Name=_ProcessId_>816<%' AND value LIKE '%WinrsHost.exe%';

SELECT COUNT(*) FROM lsass_logs
WHERE value LIKE '%Name=_ProcessId_>4484<%' AND value LIKE '%csc.exe%';

-- Anomaly investigation: LSASS appears as PID 860 (as source) and 868 (as target).
-- 860 events: win-dc-807, 15:50:18 to 15:50:27 (138 events).
-- 868 events: win-dc-807, 15:50:58 to 15:59:01 (151 events). Non-overlapping.
SELECT regexp_extract(value, '<Computer>([^<]+)<', 1) AS host,
       MIN(regexp_extract(value, 'UtcTime.>([^<]+)<', 1)) AS first_seen,
       MAX(regexp_extract(value, 'UtcTime.>([^<]+)<', 1)) AS last_seen,
       COUNT(*) AS events
FROM lsass_logs
WHERE value LIKE '%lsass.exe</Data><Data Name=_TargetProcessGUID%'
  AND value LIKE '%SourceProcessId_>860<%'
GROUP BY 1;

SELECT regexp_extract(value, '<Computer>([^<]+)<', 1) AS host,
       MIN(regexp_extract(value, 'UtcTime.>([^<]+)<', 1)) AS first_seen,
       MAX(regexp_extract(value, 'UtcTime.>([^<]+)<', 1)) AS last_seen,
       COUNT(*) AS events
FROM lsass_logs
WHERE value LIKE '%lsass.exe</Data><Data Name=_GrantedAccess%'
  AND value LIKE '%TargetProcessId_>868<%'
  AND value LIKE '%win-dc-807%'
GROUP BY 1;

-- Sysmon service starts on win-dc-807. Result: 2 (15:50:18 and 15:51:15).
-- Consistent with the dataset merging separate capture sessions. No AI flagged this.
SELECT regexp_extract(value, 'UtcTime.>([^<]+)<', 1) AS time
FROM lsass_logs
WHERE value LIKE '%<EventID>4</EventID>%'
  AND value LIKE '%win-dc-807%'
  AND value LIKE '%Started%';


-- =====================================================================
-- DATASET 2: SAM registry hive dumping (T1003.002)
-- =====================================================================

-- True event count (Gemini reported 20 in standard mode, 138 in advanced). Result: 7,016.
SELECT COUNT(*) FROM sam_logs;

-- Hosts and event types. Verifies Claude's second-host claim:
-- ar-win.nas.domain has 6 Sysmon EID 1 + 6 Security EID 4688. VERIFIED.
-- Also disproves Gemini's claim of "no registry events": EID 13 = 40, EID 12 = 8.
SELECT regexp_extract(value, '<Computer>([^<]+)<', 1) AS host,
       regexp_extract(value, '<EventID>([0-9]+)<', 1) AS event_id,
       COUNT(*) AS events
FROM sam_logs
GROUP BY 1, 2
ORDER BY 1, 3 DESC;

-- ChatGPT record IDs. Result: 6 of 6 match the claimed program and command. VERIFIED.
-- Also disproves Gemini's "the file does not contain reg save" (records 4536/4549/4562).
SELECT regexp_extract(value, '<EventRecordID>([0-9]+)<', 1) AS record,
       regexp_extract(value, 'Name=.Image.>([^<]+)<', 1) AS program,
       regexp_extract(value, 'Name=.CommandLine.>([^<]+)<', 1) AS command
FROM sam_logs
WHERE regexp_extract(value, '<EventRecordID>([0-9]+)<', 1)
      IN ('4536','4549','4562','4575','4603','5094');

-- Claude absence claim: "No Python process ever started." Result: 0. VERIFIED.
SELECT COUNT(*) FROM sam_logs
WHERE value LIKE '%<EventID>1</EventID>%'
  AND lower(regexp_extract(value, 'Name=.Image.>([^<]+)<', 1)) LIKE '%python%';

-- Positive control for the query above. Result: 55 PowerShell process starts.
SELECT COUNT(*) FROM sam_logs
WHERE value LIKE '%<EventID>1</EventID>%'
  AND lower(regexp_extract(value, 'Name=.Image.>([^<]+)<', 1)) LIKE '%powershell%';

-- Claude absence claim: "No file-creation events for the saved hives." Result: 0 rows. VERIFIED.
SELECT fname, COUNT(*) AS events
FROM (SELECT lower(regexp_extract(value, 'TargetFilename.>([^<]+)<', 1)) AS fname
      FROM sam_logs
      WHERE value LIKE '%<EventID>11</EventID>%')
WHERE fname LIKE '%temp_sam' OR fname LIKE '%temp_system'
   OR fname LIKE '%temp_security' OR fname LIKE '%windows_sam'
   OR fname LIKE '%.reg'
GROUP BY 1;

-- Positive control for the query above. Result: 94 rows (.ps1 files).
SELECT fname, COUNT(*) AS events
FROM (SELECT lower(regexp_extract(value, 'TargetFilename.>([^<]+)<', 1)) AS fname
      FROM sam_logs
      WHERE value LIKE '%<EventID>11</EventID>%')
WHERE fname LIKE '%.ps1'
GROUP BY 1;


-- =====================================================================
-- DATASET 3: DCSync (T1003.006), Windows Security log (multi-line events)
-- =====================================================================

-- True event count. Result: 4. All three models correct.
SELECT COUNT(*) FROM dcsync_logs WHERE value LIKE 'LogName=%';

-- Event types and host. Result: 3 x 4662, 1 x 4624, one DC. VERIFIED.
SELECT value, COUNT(*) AS events FROM dcsync_logs
WHERE value LIKE 'EventCode=%' OR value LIKE 'ComputerName=%'
GROUP BY 1 ORDER BY 2 DESC;

-- Does the source IP appear in the 4662 events? Result: 1 (only in the 4624 logon).
-- Confirms Gemini's detection query grouped 4662 events by an IP field that is not
-- present in them. Claude's query correctly joined 4662 to 4624 via Logon ID.
SELECT COUNT(*) FROM dcsync_logs WHERE value LIKE '%Source Network Address%';


-- =====================================================================
-- DATASET 4: WinRM lateral movement (T1021.006)
-- =====================================================================

-- True event count (Gemini reported 185). Result: 3,723.
SELECT COUNT(*) FROM winrm_logs;

-- Events per host. Claude claimed 2,606 / 1,117. Result: exact match. VERIFIED.
SELECT regexp_extract(value, '<Computer>([^<]+)<', 1) AS host, COUNT(*) AS events
FROM winrm_logs GROUP BY 1;

-- Commands launched by WinrsHost.exe on the target.
-- Result: cmd.exe /C "ipconfig" and cmd.exe /C "netstat -an" on win-host-987. VERIFIED.
-- Directly contradicts Gemini's "no indicators of malicious compromise."
SELECT regexp_extract(value, '<Computer>([^<]+)<', 1) AS host,
       regexp_extract(value, 'Name=.CommandLine.>([^<]+)<', 1) AS command
FROM winrm_logs
WHERE value LIKE '%<EventID>1</EventID>%'
  AND lower(regexp_extract(value, 'ParentImage.>([^<]+)<', 1)) LIKE '%winrshost.exe';

-- WinRM network connections (port 5985). Result: 4 (2 connections x 2 hosts). VERIFIED.
SELECT COUNT(*) FROM winrm_logs
WHERE value LIKE '%<EventID>3</EventID>%'
  AND value LIKE '%DestinationPort_>5985<%';

-- ChatGPT record IDs. Result: 6 of 6 match. VERIFIED.
-- Note: inbound connection 55911893 on the target is attributed to "System".
SELECT regexp_extract(value, '<EventRecordID>([0-9]+)<', 1) AS record,
       regexp_extract(value, '<Computer>([^<]+)<', 1) AS host,
       regexp_extract(value, 'Name=.Image.>([^<]+)<', 1) AS program,
       regexp_extract(value, 'Name=.CommandLine.>([^<]+)<', 1) AS command
FROM winrm_logs
WHERE regexp_extract(value, '<EventRecordID>([0-9]+)<', 1)
      IN ('107425424','55911844','55911860','55911926','107425504','55911893');

-- ChatGPT claim: embedded UtcTime extends past the event-header SystemTime.
-- Result: max UtcTime 18:04:32.486 vs max SystemTime 18:04:28.300. VERIFIED.
SELECT MAX(regexp_extract(value, 'UtcTime.>([^<]+)<', 1)) AS max_utctime,
       MAX(regexp_extract(value, 'SystemTime=.([0-9T:.-]+)', 1)) AS max_systemtime
FROM winrm_logs;

-- Was Gemini's "185 events" an honest report of a truncated view?
-- Events up to Gemini's last reported timestamp: 186.
-- Matches Gemini's count, consistent with it receiving only the first ~5% of the file.
SELECT COUNT(*) FROM winrm_logs
WHERE regexp_extract(value, 'SystemTime=.([0-9T:.-]+)', 1) <= '2021-11-12T17:59:46.963594000';

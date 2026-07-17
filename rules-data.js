/* ============================================
   T1082 DETECTION RULE LIBRARY — DATA
   Splunk / Sysmon detection rules built while
   running Atomic Red Team's T1082 test suite
   against a Windows 10 + Sysmon home lab.
   ============================================ */

/* Tactic display order — tells the attack-chain story
   top to bottom: recon -> escalate -> evade -> steal creds
   -> move laterally -> collect -> impact. */
const TACTIC_ORDER = [
    "Correlation",
    "Discovery",
    "Execution",
    "Defense Evasion",
    "Credential Access",
    "Lateral Movement",
    "Collection",
    "Impact"
];

const TACTIC_META = {
    "Correlation":       { color: "gold",   label: "Correlation Search" },
    "Discovery":         { color: "cyan",   label: "Discovery" },
    "Execution":         { color: "green",  label: "Execution / Priv Esc" },
    "Defense Evasion":   { color: "purple", label: "Defense Evasion" },
    "Credential Access": { color: "yellow", label: "Credential Access" },
    "Lateral Movement":  { color: "orange", label: "Lateral Movement" },
    "Collection":        { color: "blue",   label: "Collection" },
    "Impact":            { color: "red",    label: "Impact" }
};

/* Technique metadata for the left sidebar — one entry per
   distinct primary MITRE ATT&CK ID used across the ruleset. */
const TECHNIQUES = [
    { id: "ALL",     name: "All Techniques",                         tactic: "Correlation",       desc: "Show every rule" },
    { id: "T1082",   name: "System Information Discovery",           tactic: "Discovery",         desc: "Baseline host fingerprinting" },
    { id: "T1033",   name: "System Owner/User Discovery",            tactic: "Discovery",         desc: "whoami-style identity checks" },
    { id: "T1057",   name: "Process Discovery",                      tactic: "Discovery",         desc: "Enumerating running processes" },
    { id: "T1016",   name: "System Network Config Discovery",        tactic: "Discovery",         desc: "Adapters, routes, DNS, firewall" },
    { id: "T1018",   name: "Remote System Discovery",                tactic: "Discovery",         desc: "Reachability / neighbor checks" },
    { id: "T1135",   name: "Network Share Discovery",                tactic: "Discovery",         desc: "SMB share enumeration" },
    { id: "T1007",   name: "System Service Discovery",                tactic: "Discovery",         desc: "Windows service status/config" },
    { id: "T1012",   name: "Query Registry",                         tactic: "Discovery",         desc: "Registry-based fingerprinting" },
    { id: "T1059.001", name: "PowerShell",                           tactic: "Execution",         desc: "Fileless offensive tooling" },
    { id: "T1036",   name: "Masquerading",                           tactic: "Defense Evasion",   desc: "Binaries impersonating trusted files" },
    { id: "T1552.004", name: "Unsecured Credentials: Private Keys",  tactic: "Credential Access",  desc: "Certificate store enumeration" },
    { id: "T1021.004", name: "Remote Services: SSH",                 tactic: "Lateral Movement",   desc: "plink.exe / ESXi targeting" },
    { id: "T1005",   name: "Data from Local System",                 tactic: "Collection",         desc: "Local log/data staging" },
    { id: "T1490",   name: "Inhibit System Recovery",                tactic: "Impact",             desc: "Shadow copy tampering" }
];

/* ============================================
   THE RULES
   ============================================ */
const RULES = [

/* ---------- UMBRELLA CORRELATION SEARCH ---------- */
{
    num: 22,
    id: "rule-umbrella",
    isUmbrella: true,
    title: "T1082 — Automated System Information Discovery Sweep Detected",
    techniqueId: "T1082",
    techniqueName: "Correlation / Anchor: System Information Discovery",
    tactic: "Correlation",
    severity: "Dynamic (Medium → Critical)",
    catches: "Ties all 21 individual rules together by host + user + LogonId within a 15-minute window into ONE incident. This is the rule that actually solves the alert-fatigue problem — a full T1082 atomic run would otherwise fire 15-20+ separate alerts describing pieces of the same activity. Auto-escalates to CRITICAL the instant the sweep includes offensive tooling, lateral movement, credential access, defense evasion, or anti-recovery activity alongside the routine discovery noise.",
    note: "Built last, on purpose — every individual rule below was verified against raw Sysmon events first. This search doesn't introduce new detection logic; it re-derives which rule each event belongs to, groups by session, and lets severity escalate automatically when the sweep stops being 'just recon'.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
User!="NT AUTHORITY\\\\SYSTEM" User!="NT AUTHORITY\\\\NETWORK SERVICE" User!="NT AUTHORITY\\\\LOCAL SERVICE"

| eval rule_fingerprint=case(
    like(Image, "%\\\\wscript.exe") AND like(CommandLine, "%.vbs%"), "Rule1_wscript_vbs",
    like(Image, "%\\\\whoami.exe"), "Rule2_whoami",
    like(Image, "%\\\\vssadmin.exe"), "Rule3_vssadmin_INHIBIT_RECOVERY",
    like(Image, "%\\\\tasklist.exe"), "Rule4_tasklist",
    like(Image, "%\\\\cscript.exe") AND like(CommandLine, "%.vbs%"), "Rule5_cscript_vbs",
    like(Image, "*\\\\powershell.exe") AND (like(CommandLine, "%Get-NetAdapter%") OR like(CommandLine, "%Get-NetIPConfiguration%") OR like(CommandLine, "%Test-NetConnection%")), "Rule6_powershell_netrecon",
    like(Image, "%\\\\ROUTE.EXE") OR like(Image, "%\\\\route.exe"), "Rule7_route",
    like(OriginalFileName, "DismHost.exe") AND NOT like(Image, "%\\\\Windows\\\\System32\\\\%"), "Rule8_masquerading_DismHost_DEFENSE_EVASION",
    like(Image, "%\\\\systeminfo.exe"), "Rule9_systeminfo",
    like(Image, "%\\\\nbtstat.exe"), "Rule10_nbtstat",
    like(ParentCommandLine, "%plink.exe%") AND like(ParentCommandLine, "%-ssh%"), "Rule11_plink_SSH_LATERAL_MOVEMENT",
    like(Image, "%\\\\PING.EXE") AND like(ParentImage, "*\\\\powershell.exe"), "Rule12_ping_via_powershell",
    like(Image, "%\\\\net1.exe") OR (like(Image, "%\\\\net.exe") AND like(ParentImage, "*\\\\cmd.exe")), "Rule13_net_share_discovery",
    like(Image, "%\\\\ipconfig.exe"), "Rule14_ipconfig",
    like(Image, "%\\\\certutil.exe") AND like(CommandLine, "%-store%"), "Rule15_certutil_CREDENTIAL_ACCESS",
    like(Image, "%\\\\sc.exe"), "Rule16_sc_service_discovery",
    like(Image, "*\\\\powershell.exe") AND (like(CommandLine, "%downloadstring%") OR like(CommandLine, "%WinPwn%") OR like(CommandLine, "%Seatbelt%") OR like(CommandLine, "%SharpUp%") OR like(CommandLine, "%Connect-AzAccount%")), "Rule17_offensive_tooling_CRITICAL",
    like(Image, "%\\\\wevtutil.exe"), "Rule18_wevtutil_logexport",
    like(Image, "%\\\\reg.exe") OR like(Image, "%\\\\reg1.exe"), "Rule19_reg_query_export",
    like(Image, "%\\\\netsh.exe"), "Rule20_netsh_show",
    like(Image, "%\\\\arp.exe") OR like(Image, "%\\\\gpresult.exe") OR like(Image, "%\\\\wmic.exe") OR like(Image, "%\\\\dxdiag.exe") OR like(Image, "%\\\\dispdiag.exe") OR like(Image, "%\\\\powercfg.exe"), "Rule21_misc_fingerprinting",
    1=1, null())

| where isnotnull(rule_fingerprint)

| eval escalation_flag=if(like(rule_fingerprint, "%CRITICAL%") OR like(rule_fingerprint, "%LATERAL_MOVEMENT%") OR like(rule_fingerprint, "%DEFENSE_EVASION%") OR like(rule_fingerprint, "%CREDENTIAL_ACCESS%") OR like(rule_fingerprint, "%INHIBIT_RECOVERY%"), "yes", "no")

| bin _time span=15m

| stats count as total_events,
        dc(rule_fingerprint) as distinct_techniques_fired,
        values(rule_fingerprint) as techniques_fired,
        values(Image) as binaries_used,
        dc(Image) as distinct_binaries,
        values(escalation_flag) as escalation_present,
        earliest(_time) as sweep_start,
        latest(_time) as sweep_end
  by Computer, User, LogonId, _time

| where distinct_techniques_fired >= 3

| eval sweep_duration_sec=sweep_end-sweep_start
| eval sweep_start_readable=strftime(sweep_start, "%Y-%m-%d %H:%M:%S")
| eval sweep_end_readable=strftime(sweep_end, "%Y-%m-%d %H:%M:%S")

| eval contains_critical=if(like(techniques_fired, "%CRITICAL%"), "yes", "no")
| eval contains_lateral_movement=if(like(techniques_fired, "%LATERAL_MOVEMENT%"), "yes", "no")
| eval contains_defense_evasion=if(like(techniques_fired, "%DEFENSE_EVASION%"), "yes", "no")
| eval contains_credential_access=if(like(techniques_fired, "%CREDENTIAL_ACCESS%"), "yes", "no")
| eval contains_impact=if(like(techniques_fired, "%INHIBIT_RECOVERY%"), "yes", "no")

| eval incident_severity=case(
    contains_critical="yes", "CRITICAL - Offensive Tooling + Full Recon Chain",
    contains_lateral_movement="yes" OR contains_impact="yes", "CRITICAL - Lateral Movement/Ransomware Precursor + Recon Chain",
    contains_defense_evasion="yes" OR contains_credential_access="yes", "HIGH - Evasion/Credential Access + Recon Chain",
    distinct_techniques_fired>=8, "HIGH - Extensive Multi-Technique Recon Sweep",
    distinct_techniques_fired>=5, "MEDIUM - Broad Recon Sweep",
    1=1, "MEDIUM - Moderate Recon Sweep")

| eval incident_title="T1082 - Automated System Information Discovery Sweep Detected (" + tostring(distinct_techniques_fired) + " sub-techniques) on " + Computer

| eval mitre_summary="Primary: T1082 (System Information Discovery). Related: T1016, T1033, T1057, T1007, T1012, T1018, T1005, T1135, T1615, and where flagged: T1490 (Impact), T1036 (Defense Evasion), T1552.004 (Credential Access), T1021.004 (Lateral Movement), T1059.001/T1105/T1068 (Execution/Privilege Escalation tooling)."

| eval alert_fatigue_note="ALERT FATIGUE CONTEXT: without this correlation search, a single T1082 atomic run generates " + tostring(distinct_techniques_fired) + "+ separate Triggered Alerts and emails from individual rules, all describing pieces of the SAME activity. This search is the primary triage entry point. If it becomes noisy, tune the underlying rules rather than suppressing this consolidated view."

| eval analyst_note="Consolidates " + tostring(distinct_techniques_fired) + " rule triggers into one incident, same host/LogonId/15-min window, anchored to T1082. " + if(contains_critical="yes" OR contains_lateral_movement="yes" OR contains_impact="yes", "ESCALATION REQUIRED: high-severity finding present alongside recon - treat as confirmed incident.", "Discovery-only sweep - watch for escalation in the following minutes/hours.")

| table sweep_start_readable, sweep_end_readable, sweep_duration_sec,
        Computer, User, LogonId,
        incident_severity, distinct_techniques_fired, distinct_binaries,
        techniques_fired, binaries_used,
        contains_critical, contains_lateral_movement, contains_defense_evasion, contains_credential_access, contains_impact,
        incident_title, mitre_summary, alert_fatigue_note, analyst_note, total_events

| sort - distinct_techniques_fired`
},

/* ---------- RULE 1 ---------- */
{
    num: 1,
    id: "rule-1",
    title: "Suspicious wscript.exe Execution via VBS Script",
    techniqueId: "T1082",
    techniqueName: "System Information Discovery",
    sysmonNote: "Sysmon config tags this T1202 (Indirect Command Execution) — logged as a mislabel.",
    tactic: "Discovery",
    severity: "Medium – High",
    catches: "wscript.exe launching a .vbs script from a staging directory (Temp/AppData/Downloads/etc.), spawned by cmd.exe, powershell.exe, or explorer.exe. This is the classic Atomic Red Team T1082 script-based recon pattern (gatherNetworkInfo.vbs, griffon_recon.vbs).",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\wscript.exe"
CommandLine="*.vbs*"

| where like(ParentImage, "%cmd.exe") OR like(ParentImage, "%powershell.exe") OR like(ParentImage, "%explorer.exe")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| stats count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage

| where count >= 1

| eval technique_id="T1082"
| eval technique_name="System Information Discovery"
| eval sysmon_tagged_technique="T1202 - Indirect Command Execution (Sysmon config native tag)"
| eval tactic="Discovery"
| eval severity=if(like(high_integrity_flag, "%yes%"), "High", "Medium")
| eval rulename="Suspicious wscript.exe Execution via VBS Script - System/Network Info Discovery"
| eval analyst_note="wscript.exe launched a .vbs script from a non-standard working directory (Temp/AppData/etc.), spawned by cmd.exe/powershell.exe/explorer.exe. Common pattern for Atomic Red Team T1082 tests (network/system info gathering scripts). High integrity level increases confidence of malicious intent. Sysmon's own config also tags this pattern as T1202 - log the discrepancy for tuning. Correlate with EventCode=3 (network) shortly after for possible exfil."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, count,
        rulename, technique_id, technique_name, sysmon_tagged_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 2 ---------- */
{
    num: 2,
    id: "rule-2",
    title: "Suspicious whoami.exe Execution via PowerShell",
    techniqueId: "T1033",
    techniqueName: "System Owner/User Discovery",
    tactic: "Discovery",
    severity: "Medium – High",
    catches: "whoami.exe spawned directly by powershell.exe — one of the most common first commands run by both legitimate admin scripting and post-exploitation frameworks (Cobalt Strike/Empire beacons frequently run whoami as their opening move).",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\whoami.exe"
ParentImage="*\\\\powershell.exe"

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| stats count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage

| where count >= 1

| eval technique_id="T1033"
| eval technique_name="System Owner/User Discovery"
| eval tactic="Discovery"
| eval severity=if(like(high_integrity_flag, "%yes%"), "High", "Medium")
| eval rulename="Suspicious whoami.exe Execution via PowerShell - System Owner Discovery"
| eval analyst_note="whoami.exe spawned directly by powershell.exe. Common in both legit admin scripting and post-exploitation recon (e.g., Atomic Red Team T1033, Cobalt Strike/Empire beacons often run whoami as first recon command). High/System integrity level or an empty/blank ParentCommandLine (no script block, interactive-looking shell) raises suspicion significantly - correlate with EventCode=3 (network) around the same ProcessGuid/timeframe to check for C2 callback."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, count,
        rulename, technique_id, technique_name,
        tactic, severity, analyst_note`
},

/* ---------- RULE 3 ---------- */
{
    num: 3,
    id: "rule-3",
    title: "Suspicious vssadmin.exe Execution",
    techniqueId: "T1490",
    techniqueName: "Inhibit System Recovery",
    tactic: "Impact",
    severity: "Medium – Critical",
    catches: "vssadmin.exe enumerating or tampering with Volume Shadow Copies. 'list shadows' is reconnaissance and commonly precedes ransomware's actual deletion command — this is one of the most reliable early-warning indicators for ransomware anywhere in the kill chain.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\vssadmin.exe"

| where like(ParentImage, "%cmd.exe") OR like(ParentImage, "%powershell.exe") OR like(ParentImage, "%wmic.exe")

| eval command_intent=case(
    like(CommandLine, "%delete%") OR like(CommandLine, "%resize%"), "DESTRUCTIVE - shadow copy deletion/resize attempted",
    like(CommandLine, "%list%"), "RECON - shadow copy enumeration",
    1=1, "OTHER - review CommandLine")

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| stats count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(command_intent)    as intent,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage

| where count >= 1

| eval technique_id="T1490"
| eval technique_name="Inhibit System Recovery"
| eval tactic="Impact"
| eval severity=case(
    like(intent, "%DESTRUCTIVE%"), "Critical",
    like(high_integrity_flag, "%yes%"), "High",
    1=1, "Medium")
| eval rulename="Suspicious vssadmin.exe Execution - Shadow Copy Recon/Tampering"
| eval analyst_note="vssadmin.exe executed to enumerate or tamper with Volume Shadow Copies. 'list shadows' is reconnaissance and commonly precedes ransomware's actual deletion command ('vssadmin delete shadows /all /quiet'). Treat any occurrence as a high-priority precursor - correlate with subsequent vssadmin/wmic/bcdedit activity, file encryption indicators (mass file rename/write events), and check for ransom notes. This is one of the most reliable early-warning indicators for ransomware in the kill chain."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, intent, count,
        rulename, technique_id, technique_name,
        tactic, severity, analyst_note`
},

/* ---------- RULE 4 ---------- */
{
    num: 4,
    id: "rule-4",
    title: "Suspicious tasklist.exe Execution",
    techniqueId: "T1057",
    techniqueName: "Process Discovery",
    tactic: "Discovery",
    severity: "Low – High",
    catches: "tasklist.exe run outside System32 with output redirected to a file — often paired with /svc to map running processes to their hosting services, a common way to fingerprint AV/EDR tooling before attempting evasion.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\tasklist.exe"

| where like(ParentImage, "%cmd.exe") OR like(ParentImage, "%powershell.exe")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval output_redirected=if(like(ParentCommandLine, "%>%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| stats count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(output_redirected) as redirect_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage

| where count >= 1

| eval technique_id="T1057"
| eval technique_name="Process Discovery"
| eval tactic="Discovery"
| eval severity=case(
    like(redirect_flag, "%yes%") AND like(high_integrity_flag, "%yes%"), "High",
    like(redirect_flag, "%yes%") OR like(high_integrity_flag, "%yes%"), "Medium",
    1=1, "Low")
| eval rulename="Suspicious tasklist.exe Execution - Process Discovery"
| eval analyst_note="tasklist.exe executed outside System32 working directory, often with /svc flag to enumerate running processes and their hosting services (used to identify AV/EDR/security tooling). Output redirection to a file (e.g., '> processes.txt') indicates staged data collection for later exfiltration or offline review - common in Atomic Red Team T1057 tests and real-world recon prior to lateral movement or defense evasion. Correlate with subsequent file access/exfil activity on the redirected output file."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, redirect_flag, count,
        rulename, technique_id, technique_name,
        tactic, severity, analyst_note`
},

/* ---------- RULE 5 ---------- */
{
    num: 5,
    id: "rule-5",
    title: "Suspicious cscript.exe Execution via VBS Script",
    techniqueId: "T1082",
    techniqueName: "System Information Discovery",
    sysmonNote: "Sysmon config tags this T1202 (Indirect Command Execution) — same mislabel pattern as Rule 1.",
    tactic: "Discovery",
    severity: "Low – High",
    catches: "cscript.exe running a .vbs script — console-mode sibling of Rule 1. Severity rises when PowerShell wraps the call in a script block ('& {cscript ...}'), a mild obfuscation technique seen in both atomics and real droppers.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\cscript.exe"
CommandLine="*.vbs*"

| where like(ParentImage, "%cmd.exe") OR like(ParentImage, "%powershell.exe") OR like(ParentImage, "%explorer.exe")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval invoked_via_scriptblock=if(like(ParentCommandLine, "%&%{%") OR like(ParentCommandLine, "%Invoke-Expression%") OR like(ParentCommandLine, "%iex%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| stats count,
        values(CommandLine)          as cmdlines,
        values(ParentCommandLine)    as parent_cmdlines,
        values(User)                 as users,
        values(ParentUser)           as parent_users,
        values(IntegrityLevel)       as integrity_levels,
        values(CurrentDirectory)     as current_dirs,
        values(Hashes)               as hashes,
        values(invoked_via_scriptblock) as scriptblock_flag,
        values(is_high_integrity)    as high_integrity_flag
  by Computer, Image, ParentImage

| where count >= 1

| eval technique_id="T1082"
| eval technique_name="System Information Discovery"
| eval sysmon_tagged_technique="T1202 - Indirect Command Execution (Sysmon config native tag)"
| eval tactic="Discovery"
| eval severity=case(
    like(scriptblock_flag, "%yes%") AND like(high_integrity_flag, "%yes%"), "High",
    like(scriptblock_flag, "%yes%") OR like(high_integrity_flag, "%yes%"), "Medium",
    1=1, "Low")
| eval rulename="Suspicious cscript.exe Execution via VBS Script - System/Network Info Discovery"
| eval analyst_note="cscript.exe launched a .vbs script from a non-standard working directory, spawned by powershell.exe/cmd.exe/explorer.exe. PowerShell wrapping the call in a script block ('& {cscript ...}') or Invoke-Expression is a notable pattern - it's often used to obfuscate the true child process from casual log review or basic parent-child alerting, and is commonly seen in Atomic Red Team T1082 recon scripts (e.g., griffon_recon.vbs) as well as real malware droppers. Sysmon's own config also tags this pattern as T1202 - log the discrepancy for tuning. Correlate with EventCode=3 (network) shortly after for possible exfil of gathered recon data."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, scriptblock_flag, count,
        rulename, technique_id, technique_name, sysmon_tagged_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 6 ---------- */
{
    num: 6,
    id: "rule-6",
    title: "Suspicious PowerShell Network Recon Spawned by Script Host",
    techniqueId: "T1016",
    techniqueName: "System Network Configuration Discovery",
    sysmonNote: "Sysmon tags this T1202; genuinely related to T1082.",
    tactic: "Discovery",
    severity: "Low – Critical",
    catches: "PowerShell spawned by wscript.exe/cscript.exe running an extensive network-enumeration chain (adapters, routes, DNS, VM switches, PnP devices). A weighted recon_score across 8 categories separates a single benign cmdlet from a genuine automated sweep.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\\\powershell.exe"
ParentImage="*\\\\wscript.exe" OR ParentImage="*\\\\cscript.exe"

| eval network_recon_score=0
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Get-NetAdapter%"), 1, 0)
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Get-NetIPConfiguration%") OR like(CommandLine, "%Get-NetIPaddress%"), 1, 0)
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Get-NetRoute%"), 1, 0)
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Resolve-DnsName%") OR like(CommandLine, "%Get-DnsClientNrptPolicy%"), 1, 0)
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Test-NetConnection%"), 1, 0)
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Get-VMSwitch%") OR like(CommandLine, "%Get-VMNetworkAdapter%"), 1, 0)
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Get-PnpDevice%"), 1, 0)
| eval network_recon_score=network_recon_score + if(like(CommandLine, "%Get-Service%"), 1, 0)

| eval output_to_file=if(like(CommandLine, "%Out-File%") OR like(CommandLine, "%>%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| where network_recon_score >= 2

| stats count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(network_recon_score) as recon_score,
        values(output_to_file)    as output_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage

| where count >= 1

| eval technique_id="T1016"
| eval technique_name="System Network Configuration Discovery"
| eval sysmon_tagged_technique="T1202 - Indirect Command Execution (Sysmon config native tag); related to T1082 - System Information Discovery"
| eval tactic="Discovery"
| eval severity=case(
    recon_score>=6, "Critical",
    recon_score>=4 AND like(output_flag, "%yes%"), "High",
    recon_score>=2, "Medium",
    1=1, "Low")
| eval rulename="Suspicious PowerShell Network Recon Spawned by Script Host - Mass Network Enumeration"
| eval analyst_note="powershell.exe spawned by wscript.exe/cscript.exe executed an extensive network reconnaissance command chain (adapters, IP config, routes, DNS, VM switches, PnP devices, services), consistent with Atomic Red Team T1082/T1016 network discovery tests (e.g., gatherNetworkInfo.vbs). Output is written to a log file for staged collection. This is a broad, multi-faceted recon sweep rather than a single command - the recon_score field indicates how many distinct network/system enumeration categories were present in a single execution. High scores combined with file output strongly suggest deliberate, automated data staging rather than incidental admin use. Correlate with subsequent file access/exfil (EventCode=11 on the output log, EventCode=3 network connections) to determine if the collected data left the host."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, recon_score, output_flag, count,
        rulename, technique_id, technique_name, sysmon_tagged_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 7 ---------- */
{
    num: 7,
    id: "rule-7",
    title: "Suspicious route.exe Execution",
    techniqueId: "T1016",
    techniqueName: "System Network Configuration Discovery",
    tactic: "Discovery",
    severity: "Low – High",
    catches: "route.exe print run from a staging directory with output appended (>>) to a shared collection file — a low-noise, single-purpose piece of a larger automated environment-mapping script.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\ROUTE.EXE"

| where like(ParentImage, "%cmd.exe") OR like(ParentImage, "%powershell.exe")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval output_redirected=if(like(ParentCommandLine, "%>%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| stats count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(output_redirected) as redirect_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage

| where count >= 1

| eval technique_id="T1016"
| eval technique_name="System Network Configuration Discovery"
| eval tactic="Discovery"
| eval severity=case(
    like(redirect_flag, "%yes%") AND like(high_integrity_flag, "%yes%"), "High",
    like(redirect_flag, "%yes%") OR like(high_integrity_flag, "%yes%"), "Medium",
    1=1, "Low")
| eval rulename="Suspicious route.exe Execution - Network Routing Table Discovery"
| eval analyst_note="route.exe executed with 'print' to enumerate the local routing table, run from a staging directory and with output appended to a file (envinfo.txt). This is a low-noise, single-purpose recon command commonly chained alongside other network/system discovery commands (ipconfig, tasklist, systeminfo) as part of a broader environment enumeration sweep - consistent with Atomic Red Team T1016 tests. Individually low severity, but the append-to-file pattern (>>) suggests this is one entry in a running collection log being built across multiple commands - correlate with sibling commands writing to the same output file (envinfo.txt) to reconstruct the full recon sequence."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, redirect_flag, count,
        rulename, technique_id, technique_name,
        tactic, severity, analyst_note`
},

/* ---------- RULE 8 ---------- */
{
    num: 8,
    id: "rule-8",
    title: "Masquerading: DismHost.exe Executing from Non-Standard Path",
    techniqueId: "T1036",
    techniqueName: "Masquerading",
    tactic: "Defense Evasion",
    severity: "Medium – Critical",
    catches: "A binary claiming to be DismHost.exe (via embedded PE metadata) running from a GUID-named Temp folder instead of System32\\Dism. DismHost.exe has a real documented history of DLL side-loading abuse — never trust OriginalFileName/Description alone.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
OriginalFileName="DismHost.exe"

| eval expected_path="C:\\\\Windows\\\\System32\\\\Dism\\\\DismHost.exe"
| eval path_mismatch=if(NOT like(Image, "%\\\\Windows\\\\System32\\\\%"), "yes", "no")

| where path_mismatch="yes"

| eval spawned_by_recon_powershell=if(like(ParentCommandLine, "%Get-NetAdapter%") OR like(ParentCommandLine, "%Get-NetIPConfiguration%") OR like(ParentCommandLine, "%Get-PnpDevice%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| stats count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(ParentImage)       as parents,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(Image)             as actual_paths,
        values(spawned_by_recon_powershell) as recon_chain_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, OriginalFileName

| where count >= 1

| eval technique_id="T1036"
| eval technique_name="Masquerading"
| eval sub_technique="T1036.005 - Match Legitimate Name or Location (likely) / T1036.003 - Rename System Utilities"
| eval tactic="Defense Evasion"
| eval severity=case(
    like(recon_chain_flag, "%yes%") AND like(high_integrity_flag, "%yes%"), "Critical",
    like(high_integrity_flag, "%yes%"), "High",
    1=1, "Medium")
| eval rulename="Masquerading Detected - DismHost.exe Running Outside System32"
| eval analyst_note="A binary with OriginalFileName='DismHost.exe' (legitimately located at C:\\\\Windows\\\\System32\\\\Dism\\\\DismHost.exe) executed from a GUID-named subfolder under AppData\\\\Local\\\\Temp instead of its expected system path. This is a strong Masquerading indicator - either (1) a genuine copy of DismHost.exe being abused/side-loaded from an untrusted location, or (2) a malicious binary renamed to impersonate a trusted Microsoft process to blend into normal-looking logs. The GUID-named parent folder is itself suspicious, as legitimate DISM servicing operations do not typically stage from randomly-named Temp subdirectories. This process was spawned directly from the same PowerShell session performing extensive network/system reconnaissance (see Rule 6) - suggesting this may be a follow-on payload or helper process launched after recon completed, possibly for defense evasion, persistence staging, or DLL side-loading (DismHost.exe has a known history of being abused for DLL side-loading attacks). Verify the binary's actual hash against the legitimate Microsoft-signed DismHost.exe hash database - do not trust OriginalFileName/Description/Company fields alone, as these are embedded metadata that can be forged in a malicious PE."

| table Computer, users, parent_users, current_dirs, parents, parent_cmdlines, cmdlines,
        actual_paths, expected_path, hashes, integrity_levels, recon_chain_flag, count,
        rulename, technique_id, technique_name, sub_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 9 ---------- */
{
    num: 9,
    id: "rule-9",
    title: "Suspicious systeminfo.exe with Chained VM/Sandbox Detection",
    techniqueId: "T1082",
    techniqueName: "System Information Discovery",
    sysmonNote: "Sysmon config mislabels this as T1033 — systeminfo.exe is genuinely T1082.",
    tactic: "Discovery",
    severity: "Low – Critical",
    catches: "systeminfo.exe chained with a registry check against Disk\\\\Enum, SCSI, or BIOS version keys — the classic VM/sandbox-fingerprinting move used to detect analysis environments (related to T1497.001) before deciding how to behave.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\systeminfo.exe"

| eval chained_vm_check=if(like(ParentCommandLine, "%reg query%Disk\\\\Enum%") OR like(ParentCommandLine, "%reg query%SCSI%") OR like(ParentCommandLine, "%wmic%bios%") OR like(ParentCommandLine, "%wmic%computersystem%"), "yes", "no")
| eval output_redirected=if(like(ParentCommandLine, "%>%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=2m
| stats count as exec_count,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(chained_vm_check)  as vm_check_flag,
        values(output_redirected) as redirect_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1082"
| eval technique_name="System Information Discovery"
| eval related_technique=if(like(vm_check_flag, "%yes%"), "T1497.001 - Virtualization/Sandbox Evasion: System Checks", "N/A")
| eval sysmon_tagged_technique="T1033 - System Owner/User Discovery (Sysmon config mislabel - systeminfo.exe is actually T1082)"
| eval tactic=if(like(vm_check_flag, "%yes%"), "Discovery, Defense Evasion", "Discovery")
| eval severity=case(
    like(vm_check_flag, "%yes%") AND exec_count>=2, "Critical",
    like(vm_check_flag, "%yes%"), "High",
    exec_count>=2, "Medium",
    1=1, "Low")
| eval rulename="Suspicious systeminfo.exe Execution - Possible VM/Sandbox Detection Chain"
| eval analyst_note="systeminfo.exe executed one or more times within a short window from a staging directory. When chained with a registry query against HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Disk\\\\Enum (or similar SCSI/BIOS/computersystem checks), this indicates the attacker/malware is actively fingerprinting for virtualization or sandbox artifacts (VirtualBox, VMware, QEMU disk driver strings) before proceeding - a classic evasion behavior meant to abort execution or alter behavior if running in an analysis environment. Multiple systeminfo executions in quick succession within the same session may indicate repeated/automated recon (e.g., a script looping through checks) rather than a single manual command. Correlate with registry access events (EventCode=12/13) on the Disk\\\\Enum key directly for stronger confirmation, and check for conditional behavior differences following this check (e.g., process terminates or behaves differently if a VM is detected)."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, vm_check_flag, redirect_flag, exec_count,
        rulename, technique_id, technique_name, related_technique, sysmon_tagged_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 10 ---------- */
{
    num: 10,
    id: "rule-10",
    title: "Suspicious nbtstat.exe with Multiple NetBIOS Enumeration Flags",
    techniqueId: "T1016",
    techniqueName: "System Network Configuration Discovery",
    tactic: "Discovery",
    severity: "Low – High",
    catches: "nbtstat.exe run with 2+ distinct flags (-c, -n, -s, -r, -a) in a short window — a systematic, multi-angle NetBIOS sweep ahead of lateral movement planning, not a single ad-hoc lookup.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\nbtstat.exe"

| where like(ParentImage, "%cmd.exe") OR like(ParentImage, "%powershell.exe")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval flag_used=case(
    like(CommandLine, "%-c%"), "-c (cache/remote name table)",
    like(CommandLine, "%-n%"), "-n (local name table)",
    like(CommandLine, "%-s%"), "-s (sessions with IP)",
    like(CommandLine, "%-r%"), "-r (name resolution stats)",
    like(CommandLine, "%-a%"), "-a (remote by name)",
    1=1, "other/unrecognized flag")
| eval output_redirected=if(like(ParentCommandLine, "%>%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=3m
| stats count as exec_count,
        dc(flag_used)             as distinct_flags,
        values(flag_used)         as flags_used,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(output_redirected) as redirect_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1016"
| eval technique_name="System Network Configuration Discovery"
| eval tactic="Discovery"
| eval severity=case(
    distinct_flags>=2 AND like(redirect_flag, "%yes%"), "High",
    distinct_flags>=2, "Medium",
    like(redirect_flag, "%yes%") OR like(high_integrity_flag, "%yes%"), "Medium",
    1=1, "Low")
| eval rulename="Suspicious nbtstat.exe Execution - NetBIOS Enumeration Sweep"
| eval analyst_note="nbtstat.exe executed one or more times within a short window from a staging directory, using multiple distinct flags (local name table, cache, sessions, etc.) - consistent with a scripted, multi-angle NetBIOS enumeration sweep rather than a single ad-hoc lookup. Output appended to a shared collection file (e.g., FileSharing.txt) alongside other discovery commands (see related route.exe/tasklist.exe rules writing to sibling files), suggesting this is one component of a broader automated environment-mapping script. NetBIOS enumeration is commonly used to identify other hosts, shares, and domain-related name resolution info ahead of lateral movement planning. Individually low-noise, but the distinct_flags field indicates how systematic the enumeration was - 2+ distinct flags within the time window is a stronger indicator of deliberate, thorough recon than a single flag."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, flags_used, distinct_flags, redirect_flag, exec_count,
        rulename, technique_id, technique_name,
        tactic, severity, analyst_note`
},

/* ---------- RULE 11 ---------- */
{
    num: 11,
    id: "rule-11",
    title: "Suspicious plink.exe (SSH) with Plaintext Credentials Targeting ESXi",
    techniqueId: "T1021.004",
    techniqueName: "Remote Services: SSH",
    sysmonNote: "Sysmon tags the cmd.exe wrapper as T1059.003, missing the actual SSH lateral movement.",
    tactic: "Lateral Movement",
    severity: "Critical",
    catches: "cmd.exe spawning plink.exe (PuTTY) with hardcoded plaintext SSH credentials, piping a command file to a target host. Target/file names referencing ESXi mirror DarkSide ransomware's documented hypervisor-targeting behavior — encrypting one ESXi host encrypts every VM it hosts.",
    spl: "index=main source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\nImage=\"C:\\\\Windows\\\\System32\\\\cmd.exe\"\nParentCommandLine=\"*plink.exe*\" ParentCommandLine=\"*-ssh*\"\n\n| eval target_host=case(\n    match(ParentCommandLine, \"-ssh\\s+\\S+\"), replace(ParentCommandLine, \".*\\\"([a-zA-Z0-9\\.\\-_]+)\\\"\\s+-ssh.*\", \"\\1\"),\n    1=1, \"unparsed - review parent_cmdlines\")\n| eval ssh_username=case(\n    like(ParentCommandLine, \"%-l%\"), replace(ParentCommandLine, \".*-l\\s+\\\"?([a-zA-Z0-9_\\-]+)\\\"?.*\", \"\\1\"),\n    1=1, \"unknown\")\n| eval plaintext_password_exposed=if(like(ParentCommandLine, \"%-pw%\"), \"yes - CRITICAL: password visible in process logs\", \"no\")\n| eval esx_related=if(like(ParentCommandLine, \"%esx%\") OR like(ParentCommandLine, \"%vmdiscovery%\") OR like(ParentCommandLine, \"%darkside%\"), \"yes\", \"no\")\n| eval command_file=case(\n    like(ParentCommandLine, \"%-m%\"), replace(ParentCommandLine, \".*-m\\s+\\\"([^\\\"]+)\\\".*\", \"\\1\"),\n    1=1, \"none/inline\")\n\n| stats count,\n        values(CommandLine)          as cmdlines,\n        values(ParentCommandLine)    as parent_cmdlines,\n        values(User)                 as users,\n        values(ParentUser)           as parent_users,\n        values(IntegrityLevel)       as integrity_levels,\n        values(target_host)          as target_hosts,\n        values(ssh_username)         as ssh_usernames,\n        values(command_file)         as command_files,\n        values(plaintext_password_exposed) as password_exposure,\n        values(esx_related)          as esx_flag\n  by Computer, ParentImage\n\n| where count >= 1\n\n| eval technique_id=\"T1021.004\"\n| eval technique_name=\"Remote Services: SSH\"\n| eval related_technique=\"T1552.001 - Unsecured Credentials: Credentials in Files (plaintext password in command line)\"\n| eval sysmon_tagged_technique=\"T1059.003 - Windows Command Shell (Sysmon tags the cmd.exe wrapper, misses the actual SSH lateral movement)\"\n| eval tactic=\"Lateral Movement, Credential Access\"\n| eval severity=if(like(esx_flag, \"%yes%\"), \"Critical\", \"High\")\n| eval rulename=\"Suspicious plink.exe SSH Connection with Plaintext Credentials\"\n| eval analyst_note=\"cmd.exe spawned plink.exe (PuTTY SSH client) to connect to a remote/external host using hardcoded plaintext username and password directly in the command line - these credentials are now exposed in Sysmon logs, command-line auditing, and potentially process listing tools on any system where this was run. A command file was piped in via -m, indicating a scripted batch of remote commands executed over SSH rather than an interactive session. Target host and command file names reference ESXi discovery ('esx_vmdiscovery', 'esx_darkside_discovery') - this pattern is strongly associated with ransomware groups (notably DarkSide) that specifically target VMware ESXi hypervisors, since encrypting the hypervisor encrypts every hosted VM simultaneously, dramatically increasing attack impact versus targeting individual endpoints. Treat any occurrence of this pattern as a high-priority lateral movement and potential ransomware-staging event, especially if aimed at real infrastructure rather than a lab target. Immediately rotate any credentials that may have been used in cleartext, and audit the target host (atomic.local or equivalent) for unauthorized access.\"\n\n| table Computer, users, parent_users, target_hosts, ssh_usernames, command_files,\n        password_exposure, esx_flag, parent_cmdlines, cmdlines,\n        integrity_levels, count,\n        rulename, technique_id, technique_name, related_technique, sysmon_tagged_technique,\n        tactic, severity, analyst_note"
},

/* ---------- RULE 12 ---------- */
{
    num: 12,
    id: "rule-12",
    title: "Suspicious ping.exe Spawned by PowerShell Network Recon",
    techniqueId: "T1018",
    techniqueName: "Remote System Discovery",
    tactic: "Discovery",
    severity: "Low – Medium",
    catches: "ping.exe run directly by powershell.exe as part of a larger recon script — doubles as an implicit sandbox-evasion check, since isolated malware-analysis VMs often lack real internet egress and a failed ping can alter behavior.",
    spl: "index=main source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\nImage=\"C:\\\\Windows\\\\System32\\\\PING.EXE\"\nParentImage=\"*\\\\powershell.exe\"\n\n| eval ip_version=case(\n    like(CommandLine, \"%-4%\"), \"IPv4\",\n    like(CommandLine, \"%-6%\"), \"IPv6\",\n    1=1, \"unspecified\")\n| eval target_domain=case(\n    match(CommandLine, \"PING\\.EXE\\\"\\s+(\\S+)\\s\"), replace(CommandLine, \".*PING\\.EXE\\\"\\s+(\\S+)\\s.*\", \"\\1\"),\n    1=1, \"unparsed - review cmdlines\")\n| eval part_of_recon_script=if(like(ParentCommandLine, \"%Get-NetAdapter%\") OR like(ParentCommandLine, \"%Get-NetIPConfiguration%\") OR like(ParentCommandLine, \"%Test-NetConnection%\"), \"yes\", \"no\")\n| eval is_high_integrity=if(IntegrityLevel=\"High\" OR IntegrityLevel=\"System\", \"yes\", \"no\")\n\n| bin _time span=5m\n| stats count as exec_count,\n        dc(ip_version)            as distinct_ip_versions,\n        values(ip_version)        as ip_versions,\n        values(target_domain)     as target_domains,\n        values(CommandLine)       as cmdlines,\n        values(User)              as users,\n        values(ParentUser)        as parent_users,\n        values(IntegrityLevel)    as integrity_levels,\n        values(Hashes)            as hashes,\n        values(part_of_recon_script) as recon_chain_flag,\n        values(is_high_integrity) as high_integrity_flag\n  by Computer, Image, ParentImage, _time\n\n| where exec_count >= 1\n\n| eval technique_id=\"T1018\"\n| eval technique_name=\"Remote System Discovery\"\n| eval related_technique=if(like(recon_chain_flag, \"%yes%\"), \"T1497.001 - Virtualization/Sandbox Evasion: System Checks (internet reachability check)\", \"N/A\")\n| eval tactic=if(like(recon_chain_flag, \"%yes%\"), \"Discovery, Defense Evasion\", \"Discovery\")\n| eval severity=case(\n    like(recon_chain_flag, \"%yes%\") AND distinct_ip_versions>=2, \"Medium\",\n    like(recon_chain_flag, \"%yes%\"), \"Low\",\n    1=1, \"Low\")\n| eval rulename=\"ping.exe Spawned by PowerShell - Connectivity/Recon Check\"\n| eval analyst_note=\"ping.exe executed directly by powershell.exe targeting an external domain, testing both IPv4 and IPv6 reachability. When part of a larger network-recon script (see Get-NetAdapter/Test-NetConnection in ParentCommandLine), this behavior serves dual purposes: (1) confirming genuine internet egress as part of environment reconnaissance, and (2) functioning as an implicit sandbox/analysis-environment check, since isolated malware analysis VMs often lack real internet access and a failed ping may cause evasive malware to alter its behavior or abort. Individually low severity - pinging a public domain is common in legitimate scripts - but worth tracking as part of the broader recon chain rather than dismissing outright. Correlate with the parent PowerShell process (see related network recon rule) for full context.\"\n\n| table Computer, users, parent_users, target_domains, ip_versions, distinct_ip_versions,\n        cmdlines, hashes, integrity_levels, recon_chain_flag, exec_count,\n        rulename, technique_id, technique_name, related_technique,\n        tactic, severity, analyst_note"
},

/* ---------- RULE 13 ---------- */
{
    num: 13,
    id: "rule-13",
    title: "Suspicious net.exe / net1.exe Execution Sweep",
    techniqueId: "T1135",
    techniqueName: "Network Share Discovery",
    sysmonNote: "Sysmon tags this T1018 — imprecise; actual behavior is local share/config enumeration, not remote host discovery.",
    tactic: "Discovery",
    severity: "Low – Medium",
    catches: "net.exe/net1.exe running 2+ distinct subcommands (config rdr/srv, share, view, user, group) in a tight window from a staging directory — scripted SMB share/config enumeration ahead of lateral movement.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\net1.exe"
ParentImage="C:\\\\Windows\\\\System32\\\\net.exe"

| eval subcommand=case(
    like(CommandLine, "%config rdr%"), "config rdr (redirector/workstation config)",
    like(CommandLine, "%config srv%"), "config srv (server service config)",
    like(CommandLine, "%share%"), "share (SMB share enumeration)",
    like(CommandLine, "%view%"), "view (remote system share listing)",
    like(CommandLine, "%user%"), "user (account enumeration)",
    like(CommandLine, "%group%"), "group (group enumeration)",
    like(CommandLine, "%localgroup%"), "localgroup (local group enumeration)",
    1=1, "other net subcommand")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=5m
| stats count as exec_count,
        dc(subcommand)            as distinct_subcommands,
        values(subcommand)        as subcommands_used,
        values(CommandLine)       as cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1135"
| eval technique_name="Network Share Discovery"
| eval related_technique="T1016 - System Network Configuration Discovery (config rdr/srv); T1069 - Permission Groups Discovery (if user/group subcommands present)"
| eval sysmon_tagged_technique="T1018 - Remote System Discovery (Sysmon config tag - imprecise; actual behavior is local share/service enumeration, not remote host discovery)"
| eval tactic="Discovery"
| eval severity=case(
    distinct_subcommands>=3, "Medium",
    distinct_subcommands>=2, "Low",
    1=1, "Low")
| eval rulename="Suspicious net.exe/net1.exe Execution Sweep - Network Share/Config Discovery"
| eval analyst_note="net.exe (via its net1.exe worker process) executed multiple distinct subcommands within a short window from a staging directory - config rdr, config srv, and share enumerate the local system's network redirector config, server service config, and available SMB shares respectively. This trio is commonly run together as part of scripted environment discovery (Atomic Red Team T1135/T1018 tests) ahead of identifying accessible shares for lateral movement or data staging. Individually benign - net.exe is used constantly by legitimate admin scripts and even some GPOs - but 2+ distinct subcommands in a tight window from a non-standard working directory indicates deliberate, scripted enumeration rather than incidental use. Note: net.exe always spawns net1.exe internally: this parent-child relationship itself is normal Windows behavior, not evasion. Correlate with any resulting SMB connections (EventCode=3 on port 445) to see if discovered shares were subsequently accessed."

| table Computer, users, parent_users, current_dirs, cmdlines,
        hashes, integrity_levels, subcommands_used, distinct_subcommands, exec_count,
        rulename, technique_id, technique_name, related_technique, sysmon_tagged_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 14 ---------- */
{
    num: 14,
    id: "rule-14",
    title: "Suspicious ipconfig.exe Execution Sweep",
    techniqueId: "T1016",
    techniqueName: "System Network Configuration Discovery",
    tactic: "Discovery",
    severity: "Low – Medium",
    catches: "ipconfig.exe run with multiple flags (/all, /displaydns, etc.) across multiple distinct, topic-categorized output files (envinfo.txt, WcnInfo.txt, Dns.txt) — a structured, multi-file recon script rather than a single flat log.",
    spl: "index=main source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\nImage=\"C:\\\\Windows\\\\System32\\\\ipconfig.exe\"\nParentImage=\"*\\\\cmd.exe\"\n\n| eval flag_used=case(\n    like(CommandLine, \"%/all%\"), \"/all (full adapter configuration)\",\n    like(CommandLine, \"%/displaydns%\"), \"/displaydns (DNS resolver cache dump)\",\n    like(CommandLine, \"%/flushdns%\"), \"/flushdns (DNS cache flush - potential evasion/cleanup)\",\n    like(CommandLine, \"%/release%\"), \"/release (release IP - potential disruption)\",\n    like(CommandLine, \"%/renew%\"), \"/renew (renew IP lease)\",\n    1=1, \"plain ipconfig (no flag)\")\n| eval output_file=case(\n    match(ParentCommandLine, \">>\\s*\\S*\\\\\\\\([a-zA-Z0-9_]+\\.txt)\"), replace(ParentCommandLine, \".*>>\\s*\\S*\\\\\\\\([a-zA-Z0-9_]+\\.txt).*\", \"\\1\"),\n    like(ParentCommandLine, \"%>%\"), \"redirected - see parent_cmdlines\",\n    1=1, \"none/interactive\")\n\n| where like(CurrentDirectory, \"%\\\\Temp%\")\n     OR like(CurrentDirectory, \"%\\\\AppData%\")\n     OR like(CurrentDirectory, \"%\\\\Downloads%\")\n     OR like(CurrentDirectory, \"%\\\\Desktop%\")\n     OR like(CurrentDirectory, \"%\\\\Public%\")\n     OR like(CurrentDirectory, \"%\\\\ProgramData%\")\n     OR like(CurrentDirectory, \"%\\\\Roaming%\")\n\n| eval is_high_integrity=if(IntegrityLevel=\"High\" OR IntegrityLevel=\"System\", \"yes\", \"no\")\n\n| bin _time span=5m\n| stats count as exec_count,\n        dc(flag_used)             as distinct_flags,\n        values(flag_used)         as flags_used,\n        dc(output_file)           as distinct_output_files,\n        values(output_file)       as output_files,\n        values(CommandLine)       as cmdlines,\n        values(ParentCommandLine) as parent_cmdlines,\n        values(User)              as users,\n        values(ParentUser)        as parent_users,\n        values(IntegrityLevel)    as integrity_levels,\n        values(CurrentDirectory)  as current_dirs,\n        values(Hashes)            as hashes,\n        values(is_high_integrity) as high_integrity_flag\n  by Computer, Image, ParentImage, _time\n\n| where exec_count >= 1\n\n| eval technique_id=\"T1016\"\n| eval technique_name=\"System Network Configuration Discovery\"\n| eval tactic=\"Discovery\"\n| eval severity=case(\n    distinct_flags>=2 AND distinct_output_files>=2, \"Medium\",\n    distinct_flags>=2 OR distinct_output_files>=2, \"Low\",\n    1=1, \"Low\")\n| eval rulename=\"Suspicious ipconfig.exe Execution Sweep - Network Configuration/DNS Discovery\"\n| eval analyst_note=\"ipconfig.exe executed multiple times with different flags (/all, /displaydns, etc.) within a short window from a staging directory, each output appended to a distinct topic-specific collection file (e.g., envinfo.txt, WcnInfo.txt, Dns.txt). This organized, multi-file staging pattern indicates a structured automated recon script categorizing collected data by topic (general network info, wireless config, DNS cache) rather than a single flat log - a more deliberate/sophisticated collection approach than the single-file pattern seen in other discovery rules. /displaydns specifically reveals DNS resolution history, which can expose internal hostnames, recently visited internal/external resources, and infrastructure naming conventions. Correlate with the full set of sibling output files (envinfo.txt, WcnInfo.txt, Dns.txt, FileSharing.txt, osinfo.txt, processes.txt) to reconstruct the complete categorized recon collection.\"\n\n| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,\n        hashes, integrity_levels, flags_used, distinct_flags, output_files, distinct_output_files, exec_count,\n        rulename, technique_id, technique_name,\n        tactic, severity, analyst_note"
},

/* ---------- RULE 15 ---------- */
{
    num: 15,
    id: "rule-15",
    title: "Suspicious certutil.exe Certificate Store Enumeration",
    techniqueId: "T1552.004",
    techniqueName: "Unsecured Credentials: Private Keys",
    sysmonNote: "Sysmon tags this T1202 — no indirection occurring, certutil is invoked directly.",
    tactic: "Credential Access",
    severity: "Low – High",
    catches: "certutil.exe enumerating certificate stores across scopes (machine/user/enterprise) and store names (My/root/NTAuth). The 'My' store in particular can hold exportable private keys — and certutil is a well-known LOLBin also abused for payload encode/download.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\certutil.exe"
CommandLine="*-store*"

| eval store_scope=case(
    like(CommandLine, "%-enterprise%"), "enterprise (AD-published certs)",
    like(CommandLine, "%-user%"), "user (current user cert store)",
    1=1, "machine (local machine cert store)")
| eval store_name=case(
    like(CommandLine, "%My%"), "My (Personal certs - most likely to contain private keys/client certs)",
    like(CommandLine, "%root%"), "root (Trusted Root CAs)",
    like(CommandLine, "%NTAuth%"), "NTAuth (Enterprise NTAuth - AD authentication trust)",
    1=1, "other/unspecified store")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval output_redirected=if(like(ParentCommandLine, "%>%"), "yes", "no")
| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=3m
| stats count as exec_count,
        dc(store_scope)           as distinct_scopes,
        dc(store_name)            as distinct_stores,
        values(store_scope)       as scopes_queried,
        values(store_name)        as stores_queried,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(output_redirected) as redirect_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1552.004"
| eval technique_name="Unsecured Credentials: Private Keys"
| eval sysmon_tagged_technique="T1202 - Indirect Command Execution (Sysmon config mislabel - no indirection occurring, certutil invoked directly)"
| eval related_technique="T1588.002 - Obtain Capabilities: Tool (certutil is a well-known LOLBin also abused for payload download/encoding); T1553 - Subvert Trust Controls (if targeting root/NTAuth to identify trust manipulation opportunities)"
| eval tactic="Credential Access, Discovery"
| eval severity=case(
    distinct_scopes>=2 AND distinct_stores>=2, "High",
    distinct_scopes>=2 OR distinct_stores>=2, "Medium",
    1=1, "Low")
| eval rulename="Suspicious certutil.exe Certificate Store Enumeration"
| eval analyst_note="certutil.exe executed multiple times enumerating certificate stores across different scopes (machine/user/enterprise) and store names (My/root/NTAuth) within a short window, output appended to a shared collection file (envinfo.txt). Enumerating the 'My' (Personal) store is the most significant finding here - it commonly holds client authentication certificates and, depending on export settings, exportable private keys that could enable credential theft or impersonation. Enumerating 'root' and 'NTAuth' stores reveals trusted CA and AD authentication trust configuration, which can inform later trust-manipulation or certificate-based persistence/authentication attacks (e.g., rogue CA insertion, Golden Certificate style attacks). certutil.exe itself is a frequently-abused LOLBin beyond this behavior - also capable of encoding/decoding payloads and downloading files (-urlcache), so its appearance in logs at all warrants scrutiny of the full command history for this session, not just the store enumeration itself. This activity is a strong precursor to credential/certificate theft rather than a threat in isolation."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, scopes_queried, distinct_scopes, stores_queried, distinct_stores, exec_count,
        rulename, technique_id, technique_name, sysmon_tagged_technique, related_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 16 ---------- */
{
    num: 16,
    id: "rule-16",
    title: "Suspicious sc.exe Service Enumeration Sweep",
    techniqueId: "T1007",
    techniqueName: "System Service Discovery",
    sysmonNote: "Sysmon tags this T1543.003 (Create/Modify Windows Service) — mislabel; these are query-only actions.",
    tactic: "Discovery",
    severity: "Low – Critical",
    catches: "sc.exe querying status/config of 5+ distinct services in a short window — a thorough environment-fingerprinting sweep. Immediately escalates to Critical if any destructive verb (config/create/delete/stop) appears instead of a query.",
    spl: "index=main source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\nImage=\"C:\\\\Windows\\\\System32\\\\sc.exe\"\nParentImage=\"*\\\\cmd.exe\"\n\n| eval sc_action=case(\n    like(CommandLine, \"%queryex%\"), \"queryex (extended status query)\",\n    like(CommandLine, \"%query%\"), \"query (status query)\",\n    like(CommandLine, \"%qc%\"), \"qc (query config - binpath, startup type, dependencies)\",\n    like(CommandLine, \"%config%\"), \"config (MODIFY - service configuration change)\",\n    like(CommandLine, \"%create%\"), \"create (MODIFY - new service creation)\",\n    like(CommandLine, \"%delete%\"), \"delete (MODIFY - service deletion)\",\n    like(CommandLine, \"%stop%\"), \"stop (service stopped)\",\n    1=1, \"other/unrecognized action\")\n\n| eval service_name=case(\n    match(CommandLine, \"(?:query|queryex|qc)\\s+(\\S+)\"), replace(CommandLine, \".*(?:query|queryex|qc)\\s+(\\S+)\\s*.*\", \"\\1\"),\n    1=1, \"unparsed\")\n\n| eval action_is_destructive=if(like(sc_action, \"%MODIFY%\"), \"yes\", \"no\")\n\n| where like(CurrentDirectory, \"%\\\\Temp%\")\n     OR like(CurrentDirectory, \"%\\\\AppData%\")\n     OR like(CurrentDirectory, \"%\\\\Downloads%\")\n     OR like(CurrentDirectory, \"%\\\\Desktop%\")\n     OR like(CurrentDirectory, \"%\\\\Public%\")\n     OR like(CurrentDirectory, \"%\\\\ProgramData%\")\n     OR like(CurrentDirectory, \"%\\\\Roaming%\")\n\n| eval is_high_integrity=if(IntegrityLevel=\"High\" OR IntegrityLevel=\"System\", \"yes\", \"no\")\n\n| bin _time span=5m\n| stats count as exec_count,\n        dc(service_name)          as distinct_services,\n        dc(sc_action)             as distinct_actions,\n        values(service_name)      as services_queried,\n        values(sc_action)         as actions_used,\n        values(CommandLine)       as cmdlines,\n        values(ParentCommandLine) as parent_cmdlines,\n        values(User)              as users,\n        values(ParentUser)        as parent_users,\n        values(IntegrityLevel)    as integrity_levels,\n        values(CurrentDirectory)  as current_dirs,\n        values(Hashes)            as hashes,\n        values(action_is_destructive) as destructive_flag,\n        values(is_high_integrity) as high_integrity_flag\n  by Computer, Image, ParentImage, _time\n\n| where exec_count >= 1\n\n| eval technique_id=\"T1007\"\n| eval technique_name=\"System Service Discovery\"\n| eval sysmon_tagged_technique=\"T1543.003 - Create or Modify System Process: Windows Service (Sysmon config mislabel - these are query-only actions, not create/modify)\"\n| eval tactic=\"Discovery\"\n| eval severity=case(\n    like(destructive_flag, \"%yes%\"), \"Critical\",\n    distinct_services>=5, \"Medium\",\n    distinct_services>=2, \"Low\",\n    1=1, \"Low\")\n| eval rulename=\"Suspicious sc.exe Service Enumeration Sweep - System Service Discovery\"\n| eval analyst_note=\"sc.exe executed repeatedly to query status and configuration of multiple distinct Windows services (WLAN, DHCP, EAP, UPnP, WCN, native WiFi) within a short window, output appended across categorized collection files. This breadth of service querying (7+ distinct services in this sample) is consistent with a thorough, automated environment-fingerprinting script rather than a targeted admin check on one specific service. Querying network/connectivity-related services specifically (wlansvc, dhcp, eaphost, upnphost) suggests the actor is profiling the host's networking stack and configuration in detail, likely to inform further network-based attack planning. IMPORTANT: if action_is_destructive shows 'yes' for any result, this indicates a service was actually modified, created, deleted, or stopped rather than merely queried - treat that as a significantly more severe finding requiring immediate escalation regardless of the rest of this rule's context, since it represents actual system tampering rather than passive discovery.\"\n\n| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,\n        hashes, integrity_levels, services_queried, distinct_services, actions_used, distinct_actions, destructive_flag, exec_count,\n        rulename, technique_id, technique_name, sysmon_tagged_technique,\n        tactic, severity, analyst_note"
},

/* ---------- RULE 17 ---------- */
{
    num: 17,
    id: "rule-17",
    title: "CRITICAL — Offensive Security Tooling Downloaded and Executed via PowerShell",
    techniqueId: "T1059.001",
    techniqueName: "PowerShell",
    tactic: "Execution",
    severity: "Medium – Critical",
    catches: "PowerShell downloading and executing real offensive tooling (WinPwn, Seatbelt, SharpUp, Watson) fully in-memory via IEX/downloadstring, and flags an exposed plaintext Azure credential from AzureStealth. The highest-confidence indicator of active compromise anywhere in this chain.",
    spl: "index=main source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\nImage=\"*\\\\powershell.exe\"\nCommandLine=\"*downloadstring*\" OR CommandLine=\"*IEX*\" OR CommandLine=\"*Invoke-Expression*\" OR CommandLine=\"*Connect-AzAccount*\" OR CommandLine=\"*Connect-AzureAD*\"\n\n| eval tool_signature=case(\n    like(CommandLine, \"%WinPwn%\") AND like(CommandLine, \"%winPEAS%\"), \"WinPwn - winPEAS module (privesc enumeration)\",\n    like(CommandLine, \"%WinPwn%\") AND like(CommandLine, \"%itm4nprivesc%\"), \"WinPwn - itm4n privesc checks\",\n    like(CommandLine, \"%WinPwn%\") AND like(CommandLine, \"%oldchecks%\"), \"WinPwn - legacy privesc checks\",\n    like(CommandLine, \"%WinPwn%\") AND like(CommandLine, \"%otherchecks%\"), \"WinPwn - additional checks\",\n    like(CommandLine, \"%WinPwn%\") AND like(CommandLine, \"%recon%\"), \"WinPwn - general/extended recon module\",\n    like(CommandLine, \"%WinPwn%\") AND like(CommandLine, \"%RBCD%\"), \"WinPwn - Resource-Based Constrained Delegation abuse check\",\n    like(CommandLine, \"%SharpWatson%\") OR like(CommandLine, \"%Invoke-watson%\"), \"PowerSharpPack - Watson (missing patch/privesc scanner)\",\n    like(CommandLine, \"%SharpUp%\"), \"PowerSharpPack - SharpUp (privesc audit)\",\n    like(CommandLine, \"%Seatbelt%\"), \"PowerSharpPack - Seatbelt (comprehensive host/security survey)\",\n    like(CommandLine, \"%AzureStealth%\") OR like(CommandLine, \"%Connect-AzAccount%\") OR like(CommandLine, \"%Connect-AzureAD%\"), \"AzureStealth - Cloud account authentication (CREDENTIAL USE)\",\n    like(CommandLine, \"%griffon_recon%\"), \"Atomic Red Team - griffon_recon.vbs wrapper (see Rule 5)\",\n    1=1, \"other download-cradle/IEX pattern\")\n\n| eval source_repo=case(\n    match(CommandLine, \"githubusercontent\\.com/([^/]+/[^/]+)\"), replace(CommandLine, \".*githubusercontent\\.com/([^/]+/[^/]+).*\", \"\\1\"),\n    1=1, \"no external URL / local script\")\n\n| eval cloud_credential_exposed=if(like(CommandLine, \"%ConvertTo-SecureString%\") AND like(CommandLine, \"%AsPlainText%\"), \"yes - CRITICAL: plaintext password in command line\", \"no\")\n| eval is_fileless=if(like(CommandLine, \"%downloadstring%\") OR like(CommandLine, \"%IEX%\") OR like(CommandLine, \"%Invoke-Expression%\"), \"yes\", \"no\")\n| eval is_high_integrity=if(IntegrityLevel=\"High\" OR IntegrityLevel=\"System\", \"yes\", \"no\")\n\n| bin _time span=2m\n| stats count as exec_count,\n        dc(tool_signature)        as distinct_tools,\n        values(tool_signature)    as tools_used,\n        values(source_repo)       as source_repos,\n        values(CommandLine)       as cmdlines,\n        values(User)              as users,\n        values(IntegrityLevel)    as integrity_levels,\n        values(Hashes)            as hashes,\n        values(cloud_credential_exposed) as credential_exposure,\n        values(is_fileless)       as fileless_flag,\n        values(is_high_integrity) as high_integrity_flag\n  by Computer, Image, ParentImage\n\n| where exec_count >= 1\n\n| eval technique_id=\"T1059.001\"\n| eval technique_name=\"PowerShell\"\n| eval related_technique=\"T1105 - Ingress Tool Transfer (download cradle); T1068 - Exploitation for Privilege Escalation (Seatbelt/SharpUp/WinPwn are privesc-enumeration tools); T1552.001/T1078.004 - Cloud Credentials in Files (if AzureStealth present)\"\n| eval tactic=\"Execution, Privilege Escalation, Credential Access\"\n| eval severity=case(\n    like(credential_exposure, \"%yes%\"), \"Critical\",\n    distinct_tools>=3, \"Critical\",\n    distinct_tools>=1 AND like(fileless_flag, \"%yes%\"), \"High\",\n    1=1, \"Medium\")\n| eval rulename=\"CRITICAL - Offensive Security Tooling Downloaded and Executed via PowerShell\"\n| eval analyst_note=\"powershell.exe downloaded and executed, entirely in-memory (fileless), multiple well-known open-source offensive security frameworks (WinPwn, PowerSharpPack: Seatbelt/SharpUp/Watson) sourced directly from GitHub. These are genuine privilege-escalation and host/security-survey tools used extensively by real attackers and red teams - Seatbelt in particular performs an extremely thorough security configuration survey (AV/EDR presence, patch levels, credential storage locations, etc.) that materially aids an attacker's next steps. The download-cradle pattern (IEX + downloadstring) means no file ever touches disk, evading file-based AV/EDR detection and leaving PowerShell Script Block Logging (Event ID 4104) as the primary source of truth for what code actually executed - if that logging is not enabled, the true payload content is invisible beyond this top-level command line. One event shows AzureStealth.ps1 authenticating to Azure/Azure AD using a hardcoded, now-exposed plaintext password - this represents actual cloud account access, not just host-level activity, and that credential must be treated as compromised immediately. This is the highest-confidence indicator of genuine compromise (or full-scope red-team activity) in the entire session - treat as a confirmed incident requiring full IR response, not routine alert triage.\"\n\n| table Computer, users, integrity_levels, tools_used, distinct_tools, source_repos,\n        credential_exposure, fileless_flag, cmdlines, hashes, exec_count,\n        rulename, technique_id, technique_name, related_technique,\n        tactic, severity, analyst_note"
},

/* ---------- RULE 18 ---------- */
{
    num: 18,
    id: "rule-18",
    title: "Windows Event Log Export/Enumeration Sweep",
    techniqueId: "T1005",
    techniqueName: "Data from Local System",
    sysmonNote: "Sysmon tags this T1070.001 (Clear Windows Event Logs) — mislabel; no 'cl' (clear) verb present, only 'epl' (export) and 'al' (archive-config).",
    tactic: "Collection",
    severity: "Low – Critical",
    catches: "wevtutil systematically exporting 8+ distinct operational event logs (WLAN, WCM, WWAN, Firewall x4, Hyper-V networking) — explicitly distinguishes 'export' from 'clear' to avoid mistaking data staging for anti-forensics.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\\\Windows\\\\System32\\\\wevtutil.exe"
ParentImage="*\\\\cmd.exe"

| eval wevtutil_action=case(
    like(CommandLine, "% cl %") OR like(CommandLine, "%\\\\scl\\\\s%"), "cl (CLEAR LOG - DESTRUCTIVE, actual T1070.001)",
    like(CommandLine, "%epl%"), "epl (export log to file)",
    like(CommandLine, "% al %"), "al (query/set auto-archive setting)",
    like(CommandLine, "%sl%") AND NOT like(CommandLine, "%epl%"), "sl (set log properties - could disable logging)",
    1=1, "other wevtutil action")

| eval log_targeted=case(
    like(CommandLine, "%WLAN-AutoConfig%"), "WLAN-AutoConfig (wireless connection history)",
    like(CommandLine, "%Wcmsvc%"), "WCM (Windows Connection Manager - network profiles)",
    like(CommandLine, "%WWAN%"), "WWAN (mobile broadband)",
    like(CommandLine, "%Firewall%ConnectionSecurity%"), "Windows Firewall - Connection Security",
    like(CommandLine, "%Firewall%Verbose%"), "Windows Firewall - Verbose",
    like(CommandLine, "%Firewall%"), "Windows Firewall - Main",
    like(CommandLine, "%Hyper-V-VmSwitch%"), "Hyper-V VMSwitch (virtual networking)",
    like(CommandLine, "%VMMS-Networking%"), "Hyper-V VMMS Networking",
    1=1, "other event log")

| eval action_is_destructive=if(like(wevtutil_action, "%DESTRUCTIVE%"), "yes", "no")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=5m
| stats count as exec_count,
        dc(log_targeted)          as distinct_logs,
        values(log_targeted)      as logs_targeted,
        values(wevtutil_action)   as actions_used,
        values(CommandLine)       as cmdlines,
        values(ParentCommandLine) as parent_cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(action_is_destructive) as destructive_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1005"
| eval technique_name="Data from Local System"
| eval sysmon_tagged_technique="T1070.001 - Clear Windows Event Logs (Sysmon config mislabel - no 'cl' verb present in any of these events, only 'epl'/export and 'al'/archive-config)"
| eval related_technique="T1082/T1016 - the specific logs targeted (WLAN, WCM, WWAN, Firewall, Hyper-V networking) mirror the same network/virtualization discovery themes seen in Rules 6, 9, 12, 14"
| eval tactic="Collection"
| eval severity=case(
    like(destructive_flag, "%yes%"), "Critical",
    distinct_logs>=8, "Medium",
    distinct_logs>=3, "Low",
    1=1, "Low")
| eval rulename="Windows Event Log Export/Enumeration Sweep - Data Staging"
| eval analyst_note="wevtutil.exe systematically exported (epl) and checked archive settings (al) for ten distinct operational event logs covering wireless/network connectivity (WLAN-AutoConfig, WCM, WWAN), host firewall activity (four Firewall log variants), and Hyper-V virtual networking (VmSwitch, VMMS-Networking), all staged to .evtx files in a Temp working directory. This is NOT log clearing - Sysmon's T1070.001 tag on two of these events is a mislabel, since only 'epl' (export) and 'al' (archive-config, a benign query/setting) verbs appear, never 'cl' (clear). The actual behavior here is comprehensive LOCAL DATA COLLECTION of historical network activity and firewall decisions, likely to analyze the host's networking history and security posture in detail, or to stage this data for later exfiltration. The specific focus on Hyper-V networking logs alongside earlier VM-detection activity suggests continued interest in virtualization infrastructure, consistent with the plink.exe/ESXi targeting pattern. IMPORTANT: if a follow-up 'wevtutil cl' command appears in this same session or LogonId, that represents genuine T1070.001 anti-forensics activity and must be escalated to Critical immediately, as it would indicate the actor is now destroying evidence rather than just collecting it."

| table Computer, users, parent_users, current_dirs, parent_cmdlines, cmdlines,
        hashes, integrity_levels, logs_targeted, distinct_logs, actions_used, destructive_flag, exec_count,
        rulename, technique_id, technique_name, sysmon_tagged_technique, related_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 19 ---------- */
{
    num: 19,
    id: "rule-19",
    title: "Suspicious reg.exe Query/Export Sweep",
    techniqueId: "T1012",
    techniqueName: "Query Registry",
    tactic: "Discovery",
    severity: "Low – Critical",
    catches: "reg.exe querying/exporting across VM-fingerprinting (Disk\\\\Enum, BIOS keys), credential-provider, and network-policy registry areas — instantly escalates to Critical if a write verb (add/delete/import) ever appears instead of query/export.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\\\reg.exe"
ParentImage="*\\\\cmd.exe"

| eval reg_action=case(
    like(CommandLine, "%export%") OR like(CommandLine, "%Export%"), "export (collection - full key export to file)",
    like(CommandLine, "%query%") OR like(CommandLine, "%QUERY%"), "query (read single value/key)",
    like(CommandLine, "%add%"), "add (MODIFY - registry write)",
    like(CommandLine, "%delete%"), "delete (MODIFY - registry deletion)",
    like(CommandLine, "%import%"), "import (MODIFY - registry write from file)",
    1=1, "other/unrecognized action")

| eval key_category=case(
    like(CommandLine, "%Disk\\\\Enum%") OR like(CommandLine, "%SystemBiosVersion%") OR like(CommandLine, "%VideoBiosVersion%"), "VM/Sandbox Fingerprinting (T1497.001-relevant)",
    like(CommandLine, "%Credential Provider%") OR like(CommandLine, "%Credential Providers%"), "Credential Provider Enumeration (T1552-adjacent)",
    like(CommandLine, "%Cryptography%") AND like(CommandLine, "%MachineGuid%"), "Machine Identification (MachineGuid)",
    like(CommandLine, "%Wlansvc%") OR like(CommandLine, "%dot3svc%") OR like(CommandLine, "%WcmSvc%") OR like(CommandLine, "%Wireless%") OR like(CommandLine, "%WiredL2%") OR like(CommandLine, "%NetworkList%"), "Network/WLAN Configuration Policy",
    like(CommandLine, "%Winsock%"), "Winsock Configuration (network stack)",
    like(CommandLine, "%CurrentVersion%") AND (like(CommandLine, "%CurrentBuildNumber%") OR like(CommandLine, "%ProductName%")), "OS Version Identification",
    like(CommandLine, "%EnterpriseDataProtection%") OR like(CommandLine, "%PolicyManager%"), "Enterprise/MDM Policy Configuration",
    like(CommandLine, "%HomeGroup%"), "Legacy HomeGroup Service Config",
    like(CommandLine, "%International\\\\Geo%"), "Locale/Geo Configuration",
    like(CommandLine, "%Winlogon\\\\Notifications%"), "Winlogon Notification Packages (persistence-relevant location)",
    1=1, "other registry area")

| eval action_is_destructive=if(like(reg_action, "%MODIFY%"), "yes", "no")
| eval touches_vm_fingerprint=if(like(key_category, "%VM/Sandbox%"), "yes", "no")
| eval touches_credential_config=if(like(key_category, "%Credential%"), "yes", "no")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=5m
| stats count as exec_count,
        dc(key_category)          as distinct_categories,
        values(key_category)      as categories_touched,
        values(reg_action)        as actions_used,
        values(CommandLine)       as cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(action_is_destructive) as destructive_flag,
        values(touches_vm_fingerprint) as vm_check_flag,
        values(touches_credential_config) as credential_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, Image, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1012"
| eval technique_name="Query Registry"
| eval related_technique="T1005 - Data from Local System (export actions write full key contents to files); T1497.001 - Virtualization/Sandbox Evasion (Disk\\\\Enum, BIOS version checks); T1552 - Unsecured Credentials (Credential Provider enumeration)"
| eval tactic="Discovery, Collection"
| eval severity=case(
    like(destructive_flag, "%yes%"), "Critical",
    like(vm_check_flag, "%yes%") AND like(credential_flag, "%yes%"), "Medium",
    distinct_categories>=6, "Medium",
    1=1, "Low")
| eval rulename="Suspicious reg.exe Query/Export Sweep - Registry Reconnaissance and Collection"
| eval analyst_note="reg.exe executed numerous query and export operations across a wide range of registry areas within a short window, from a staging directory. All commands observed are read-only (query/export) - no add/delete/import actions present, so no registry tampering has occurred. Notable categories: (1) VM/sandbox fingerprinting via Disk\\\\Enum and BIOS version keys, consistent with the evasion-check pattern seen in the systeminfo-chain rule; (2) Credential Provider enumeration, which reveals which authentication mechanisms (smartcard, biometric, password) are active on the host - useful recon before planning a credential-theft or MFA-bypass approach, though not itself credential theft; (3) broad network/WLAN/Winsock policy export, consistent with the network-configuration-discovery theme seen across many other rules in this session; (4) MachineGuid query, often used for host fingerprinting/tracking. The export actions in particular stage full registry key contents to .reg/.txt files, meaning this data - including any embedded configuration secrets - is now sitting in the Temp directory pending exfiltration or further use. This rule fires broadly on volume/breadth alone even without any single high-risk key, since the sheer scope of registry areas covered indicates a thorough, automated reconnaissance script rather than a targeted admin lookup."

| table Computer, users, parent_users, current_dirs, cmdlines,
        hashes, integrity_levels, categories_touched, distinct_categories, actions_used, destructive_flag, vm_check_flag, credential_flag, exec_count,
        rulename, technique_id, technique_name, related_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 20 ---------- */
{
    num: 20,
    id: "rule-20",
    title: "Suspicious netsh.exe Show/Enumeration Sweep",
    techniqueId: "T1016",
    techniqueName: "System Network Configuration Discovery",
    tactic: "Discovery",
    severity: "Low – Critical",
    catches: "netsh.exe enumerating firewall rules, WLAN/LAN/MBN config, WFP state, and tunneling-protocol status (httpstunnel/Teredo — potential covert-channel recon). Escalates to Critical the rare time a command reveals a saved Wi-Fi password in plaintext (key=clear).",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\\\netsh.exe"
ParentImage="*\\\\cmd.exe"
CommandLine="*show*"

| eval netsh_area=case(
    like(CommandLine, "%advfirewall%"), "Firewall Rules/Profile (advfirewall)",
    like(CommandLine, "%httpstunnel%") OR like(CommandLine, "%teredo%"), "Tunneling Protocol Status (potential covert-channel recon)",
    like(CommandLine, "%int ipv6%") OR like(CommandLine, "%namespace%"), "IPv6/Namespace Configuration",
    like(CommandLine, "%lan show%"), "Wired LAN Configuration",
    like(CommandLine, "%mbn%"), "Mobile Broadband (MBN) Configuration",
    like(CommandLine, "%wfp%"), "Windows Filtering Platform (WFP) State/Events",
    like(CommandLine, "%winsock%"), "Winsock Protocol Catalog",
    like(CommandLine, "%wlan%") OR like(CommandLine, "%\\\\swl\\\\s%"), "Wireless (WLAN) Configuration",
    1=1, "other netsh area")

| eval potential_covert_channel_check=if(like(netsh_area, "%Tunneling%"), "yes", "no")
| eval reveals_key=if(like(CommandLine, "%key=clear%"), "yes - CRITICAL: saved credentials exposed", "no")
| eval output_to_file=if(like(CommandLine, "%file=%"), "yes", "no")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=5m
| stats count as exec_count,
        dc(netsh_area)             as distinct_areas,
        values(netsh_area)         as areas_touched,
        values(CommandLine)        as cmdlines,
        values(User)               as users,
        values(ParentUser)         as parent_users,
        values(IntegrityLevel)     as integrity_levels,
        values(CurrentDirectory)   as current_dirs,
        values(Hashes)             as hashes,
        values(potential_covert_channel_check) as tunnel_check_flag,
        values(reveals_key)        as key_exposure_flag,
        values(output_to_file)     as file_output_flag,
        values(is_high_integrity)  as high_integrity_flag
  by Computer, Image, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1016"
| eval technique_name="System Network Configuration Discovery"
| eval related_technique="T1518.001 - Security Software Discovery (firewall rule enumeration reveals security posture); T1573 - Encrypted Channel (httpstunnel/teredo checks are precursor recon for covert channel use); T1550 - if key=clear ever used, that would be T1552.001 Credentials in Files"
| eval tactic="Discovery"
| eval severity=case(
    like(key_exposure_flag, "%yes%"), "Critical",
    like(tunnel_check_flag, "%yes%") AND distinct_areas>=5, "Medium",
    distinct_areas>=6, "Medium",
    1=1, "Low")
| eval rulename="Suspicious netsh.exe Show/Enumeration Sweep - Network Stack and Firewall Discovery"
| eval analyst_note="netsh.exe executed a broad series of read-only 'show' commands across firewall rules, wireless/LAN/mobile-broadband configuration, Windows Filtering Platform state, Winsock catalog, and tunneling protocol status, all from a staging directory. All observed commands are enumeration only - no 'set'/'add'/'delete' verbs present, so no firewall or network configuration has been modified. Two aspects merit specific attention: (1) the full verbose firewall rule dump ('show rule name=all verbose') reveals the complete allow/block posture of the host, which is valuable reconnaissance for planning how to blend malicious traffic in or identify an already-permitted port/application to abuse; (2) the httpstunnel and teredo status checks specifically query tunneling-protocol availability, which is worth flagging as potential precursor recon for a covert command-and-control channel or firewall-bypass method, should the actor need one later. No wlan/lan profile command in this batch used 'key=clear', so no saved Wi-Fi credentials have been exposed - but if that flag ever appears in a future event, escalate immediately as it would reveal plaintext saved wireless passwords."

| table Computer, users, parent_users, current_dirs, cmdlines,
        hashes, integrity_levels, areas_touched, distinct_areas, tunnel_check_flag, key_exposure_flag, file_output_flag, exec_count,
        rulename, technique_id, technique_name, related_technique,
        tactic, severity, analyst_note`
},

/* ---------- RULE 21 ---------- */
{
    num: 21,
    id: "rule-21",
    title: "Remaining T1082 Miscellaneous System Fingerprinting Commands",
    techniqueId: "T1082",
    techniqueName: "System Information Discovery",
    tactic: "Discovery",
    severity: "Low – Medium",
    catches: "Groups the low-noise leftover fingerprinting commands (arp, dxdiag, dispdiag, powercfg, set) into one rule, weighted so gpresult (Group Policy exposure) and wmic qfe (missing patches — informs exploit selection) drive the only path to Medium severity.",
    spl: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
ParentImage="*\\\\cmd.exe"
(Image="*\\\\arp.exe" OR Image="*\\\\dispdiag.exe" OR Image="*\\\\dxdiag.exe" OR Image="*\\\\gpresult.exe" OR Image="*\\\\powercfg.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\cmd.exe")
(CommandLine="*arp*" OR CommandLine="*dispdiag*" OR CommandLine="*dxdiag*" OR CommandLine="*gpresult*" OR CommandLine="*powercfg*" OR CommandLine="* set *" OR CommandLine="*wmic qfe*")

| eval command_type=case(
    like(CommandLine, "%gpresult%"), "gpresult (Group Policy enumeration - HIGH VALUE: reveals domain security policy)",
    like(CommandLine, "%wmic qfe%"), "wmic qfe (installed hotfix/patch enumeration - HIGH VALUE: informs exploit/vuln selection)",
    like(CommandLine, "%arp%"), "arp -a (ARP cache/local network neighbor enumeration)",
    like(CommandLine, "%dxdiag%"), "dxdiag (DirectX/hardware diagnostics)",
    like(CommandLine, "%dispdiag%"), "dispdiag (display diagnostics dump)",
    like(CommandLine, "%powercfg%"), "powercfg (battery/power report)",
    like(CommandLine, "% set %") OR like(CommandLine, "%set processor%") OR like(CommandLine, "%set u%"), "set (environment variable dump - CPU/user info)",
    1=1, "other miscellaneous fingerprinting command")

| eval is_high_value=if(like(command_type, "%HIGH VALUE%"), "yes", "no")
| eval output_redirected=if(like(CommandLine, "%>%"), "yes", "no")

| where like(CurrentDirectory, "%\\\\Temp%")
     OR like(CurrentDirectory, "%\\\\AppData%")
     OR like(CurrentDirectory, "%\\\\Downloads%")
     OR like(CurrentDirectory, "%\\\\Desktop%")
     OR like(CurrentDirectory, "%\\\\Public%")
     OR like(CurrentDirectory, "%\\\\ProgramData%")
     OR like(CurrentDirectory, "%\\\\Roaming%")

| eval is_high_integrity=if(IntegrityLevel="High" OR IntegrityLevel="System", "yes", "no")

| bin _time span=5m
| stats count as exec_count,
        dc(command_type)          as distinct_commands,
        values(command_type)      as commands_used,
        values(CommandLine)       as cmdlines,
        values(User)              as users,
        values(ParentUser)        as parent_users,
        values(IntegrityLevel)    as integrity_levels,
        values(CurrentDirectory)  as current_dirs,
        values(Hashes)            as hashes,
        values(is_high_value)     as high_value_flag,
        values(output_redirected) as redirect_flag,
        values(is_high_integrity) as high_integrity_flag
  by Computer, ParentImage, _time

| where exec_count >= 1

| eval technique_id="T1082"
| eval technique_name="System Information Discovery"
| eval related_technique="T1615 - Group Policy Discovery (gpresult); T1518.001-adjacent - patch/hotfix enumeration informs vulnerability targeting (wmic qfe); T1016/T1018 - ARP cache reveals local network neighbors"
| eval tactic="Discovery"
| eval severity=case(
    like(high_value_flag, "%yes%") AND distinct_commands>=3, "Medium",
    like(high_value_flag, "%yes%"), "Low",
    1=1, "Low")
| eval rulename="Remaining T1082 Miscellaneous System Fingerprinting Commands"
| eval analyst_note="A batch of miscellaneous system-fingerprinting commands executed from a staging directory, output appended to categorized collection files, consistent with the same automated recon script covered across this entire rule family. Two commands in this batch carry disproportionate value to an attacker despite the low-noise grouping: (1) 'gpresult /scope:computer /v' dumps the complete effective Group Policy configuration, revealing domain security settings, applied GPOs, and potentially security-relevant restrictions the actor would need to work around; (2) 'wmic qfe' enumerates every installed hotfix/patch on the host, which directly tells an attacker which specific vulnerabilities remain unpatched and can be targeted for exploitation - this is meaningfully more actionable than most discovery commands in this session. The remaining commands (arp, dxdiag, dispdiag, powercfg, set) are lower-value hardware/environment fingerprinting, included here for completeness rather than as standalone high-priority indicators. This rule intentionally groups several low-individual-value commands together rather than creating a separate alert for each, since none of them independently warrant a dedicated detection - the value is in recognizing the pattern collectively as part of the broader reconnaissance sweep."

| table Computer, users, parent_users, current_dirs, cmdlines,
        hashes, integrity_levels, commands_used, distinct_commands, high_value_flag, redirect_flag, exec_count,
        rulename, technique_id, technique_name, related_technique,
        tactic, severity, analyst_note`
}

]; /* end RULES */

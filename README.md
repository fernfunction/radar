# Radar

Radar is a process monitor for Windows that continuously records the lifecycle of everything that runs on your machine: when a program is born, what it does while it lives, and when it ends. The focus is visibility into short-lived programs, the ones that appear for a few seconds and vanish before you notice. Task Manager only shows the present; Radar keeps the history.

All collection and analysis happen on your machine. Nothing leaves it unless you explicitly allow it. Radar is not an antivirus: it does not block or remove anything. It shows, explains, and helps you decide.

## How it works

Radar has two parts that work together:

- A collector that runs in the background and records events, even with the window closed.
- An interface where you browse the history, investigate, and adjust everything.

The collector lives in the Windows tray, next to the clock. From there you open Radar, see the collection status, and can pause, resume, or stop it. When something critical is found, a notification takes you straight to the detail.

To capture the real creation of processes and per-program network activity, the collector asks for elevation (the Windows permission prompt). If you decline, it keeps working in a reduced mode with less detail.

The first time you open Radar, an assistant explains what will be collected, lets you pick the initial profile, and confirms where the data will live.

## Views

**Dashboard.** A summary of the last 24 hours and the last 7 days: how many new processes, how many short-lived ones worth noting, how many persistence entries were added, and the upload volume from untrusted programs. It also shows recent findings written in plain language, the ranking by score, and the health of the collection (events per minute, database size, and memory use).

**Timeline.** The chronology of what happened, with an hourly density chart (handy for answering "what ran at 3 in the morning?") and system context markers such as logon, sleep, and network change. The filters combine by period, user, and other criteria.

**Short-lived.** The heart of Radar. It groups by program the executions that last only a few seconds, with frequency and regularity statistics. Programs that run at very regular intervals stand out on their own. Legitimate, repetitive executions can be suppressed, always in an auditable way: Radar shows how many were hidden.

**Signatures.** Everything grouped by the state of the digital signature: valid and trusted, with caveats, invalid (file changed after being signed), revoked certificate, self-signed, or unsigned. This is also where masquerading shows up (programs trying to pass for others) and the certificate issuers that are rare on your machine.

**Network.** Network activity seen per program: who each one talked to, how much it sent and received, whether the connection used a direct IP without a domain lookup, and whether there was a disproportionate upload. It includes a simple graph linking each process to its destinations.

**Persistence.** The places where programs install themselves to start on their own (startup registry keys, Startup folders, scheduled tasks, services, and others). It shows what changed over time and tries to link each new persistence to the program that created it.

**Process tree.** The full lineage of who created whom, including processes that have already died. Task Manager only sees what is alive right now; here you navigate the history.

**Search.** Searches by name, path, hash, domain, IP, certificate issuer, or user.

## The process dossier

Clicking any execution opens the dossier, the full record of that process:

- Identity: name, path, hash, size, user, integrity level, whether it ran elevated, and the signature state.
- Explained score: the suspicion score broken down signal by signal, with the evidence behind each point. Never a bare number without justification.
- Replay: a second by second reconstruction of what the process did, like a movie. Who created it, which domains it resolved, who it connected to, which files it read or created, which modules it loaded, and when it ended.
- Tabs for network, files, origin and chain, related persistence, previous executions of the same program, and your notes.

The actions available in the dossier:

- Mark as trusted, suspicious, or under investigation. Trust is tied to the hash, path, and issuer, never to the name alone.
- Copy the indicators to paste elsewhere.
- Export an investigation report as HTML or JSON.
- Generate an assisted removal plan: a checklist with everything Radar knows (persistence, created files, sibling processes). Carrying out the removal is up to you.
- End the process, open the file's folder, or look up the hash reputation on the web (only the hash is sent, never the file).

## How Radar evaluates

Each execution gets a suspicion score added up from several signals and always shown broken down, with the evidence behind each point. The bands are Informational, Attention, Suspicious, and Critical.

Among the signals Radar considers:

- Masquerading: a system program name out of place, names that look like the real ones, metadata that does not match the signature, a document icon on an executable, and double extensions (like invoice.pdf.exe).
- Suspicious command line: encoded commands, disguised downloads, and legitimate Windows tools used out of context.
- Short life with network upload and beaconing (periodic, very regular connections, typical of a program that keeps "calling home").
- Indicators in the file itself: high entropy (a sign of packing), double extension, text direction trick, and a random-looking name.
- Origin and chain: what triggered the process (scheduled task, service, persistence) and any mismatch between the declared parent and the real creator.
- Novelty and frequency: first time seen and how rare it is on this machine.

Radar learns what is normal on this machine during an initial period. After that, novelty counts toward an investigation, but is never guilt on its own.

## What Radar collects

Collection is split into modules you turn on and off independently. When you turn any of them off, Radar explains exactly what you stop seeing.

| Module | What it covers |
| ------ | -------------- |
| Processes (core) | The foundation of everything: process start and stop. Without it, almost no feature works. |
| Network (TCP/UDP per process) | Each program's connections, communication replay, upload signals, and the network graph. |
| DNS (queries per process) | Links connections to domains and flags a direct IP with no prior lookup. |
| Files, sensitive reads | Reads of credential vaults, wallets, and tokens. The strongest sign of data theft. |
| Files, executable and script drops | File lineage: who created which executable and what it became when it ran. |
| Files, self deletion detection | Binaries that delete themselves after running, a trick to erase traces. |
| Modules and Image Load | An unsigned DLL loaded inside a trusted process (sideloading). |
| Persistence scan | Detects and correlates new automatic startup points. |
| Baseline and prevalence | The "never seen before" and how often each program has run on this machine. |

## Settings

**Collection profiles.** Shortcuts that preconfigure the modules: Complete, Balanced (the default), Minimal, or Custom. Changing any module switches the profile to Custom.

**Collection exclusions.** Whatever you exclude here is not even written to disk. This is different from the trust list, which only filters what is shown. You can exclude by path prefix (for example a confidential work folder), by program name, or by certificate issuer.

**Data storage.** Shows the folder where everything lives (event database, settings, and logs) and lets you validate and migrate to another location without losing the history.

**Retention.** How many days to keep raw events and the cap on database size in MB. What expires is not thrown away: it becomes a statistical summary, so the historical counts still hold.

**Frequency of periodic actions.** How often to scan for persistence (in minutes), the size of the signature verification batch (in seconds), the database compaction interval (in seconds), and the maximum number of notifications per hour. Shorter intervals detect faster and use a bit more processor.

**Lifecycle and notifications.** Stop collection when the interface closes (off by default, because with this on the short-lived programs that run while the app is closed become invisible forever). Start collection together with Windows. Turn the real time alerts on or off and choose from which level to alert: Critical only (the default), Suspicious or above, or Attention or above. The hourly cap prevents notification overload.

**Privacy and language.** Zero telemetry by default and no external lookup without your approval. Optionally, you can update the curated lists over the internet (once a week) and look up hash reputation through an API, using a key you provide yourself. The language switches between Portuguese and English. This is also where the short life threshold in seconds lives, that is, what counts as short-lived (default of 30 seconds).

**Visibility modes.** You decide whether to see only what passes the filters (the default), see everything with the filtered items just marked, or see only what is above a score threshold.

**Operation and support.** Open the logs folder, open the settings.json file for advanced tweaks, and enable Windows process-creation auditing (event 4688) as a complementary source.

**Advanced tweaks (settings.json).** The finest parameters live in the settings.json file, inside the data folder: the weight of each score signal, the baseline learning period, the safety limits of the periodic routines, the log level, and others. Edit with care.

## Privacy

- Everything is processed and stored on your machine.
- What you exclude from collection is never written.
- No lookup leaves the machine unless you turn it on.
- When looking up reputation, only the hash is sent, never the file.
- The operation logs do not keep command lines, domains, or the user's hashes.

## What Radar does not do

Radar is honest about its own limits:

- It is not an antivirus: it does not block or remove.
- A high score is not a malware verdict, it is an invitation to investigate.
- Programs with kernel privilege can blind any ordinary monitor, including this one.
- Radar does not look at the content of the traffic: it sees who and how much, not what.
- Collection only sees from the moment it was installed onward.

## Requirements

Windows 10 or 11. For full collection (real process creation and per-program network), the collector needs elevation. Without elevation, Radar works in a reduced mode and can use Windows event 4688 auditing as a complementary source.

## Where the data lives

By default in the %LOCALAPPDATA%\fradar folder: the event database (radar.db), the settings (settings.json), the logs, the curated lists, and the exported reports. You can change this location in the settings.

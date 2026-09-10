## Detection in Action

A real, end-to-end walkthrough: an automated SSH brute-force launched from the isolated Kali attacker VM, caught, correlated, escalated, enriched, and resolved — entirely by the pipeline described above.

**1. The attack** — Hydra running an automated SSH brute-force from Kali against the Linux victim.
![Kali running an SSH brute-force attack](screenshots/01-kali-attacker.png)

**2. Network-layer detection** — Suricata, running on pfSense, flags the malformed SSH handshake pattern as the brute-force tool repeatedly connects.
![Suricata SSH invalid banner alerts on pfSense](screenshots/02-suricata-alert.png)

**3. Correlation in the SIEM** — Wazuh's dashboard shows the network-side detection (`pfSense.home.arpa`) and the host-side detection (`ubuntu-admin`, PAM authentication failures) side by side, in the same timeframe — proving both layers caught the same incident independently.
![Correlated Suricata and Wazuh host alerts](screenshots/03-wazuh-detection.png)

**4. Automated handoff to TheHive** — The custom Wazuh→TheHive integration script forwards the alert automatically. Because this alert hit Wazuh rule level 10, it was auto-promoted straight into a full case (no analyst click required) — visible here alongside a lower-severity alert (level 8) that correctly stayed in the queue for manual triage instead.
![Auto-created TheHive alert and case](screenshots/04-thehive-auto-alert.png)

**5. Enrichment via Cortex** — The attacker's IP, already attached as an observable by the automation, enriched on demand with a VirusTotal lookup through Cortex.
![Cortex VirusTotal enrichment on the attacker IP](screenshots/05-cortex-enrichment.png)

**6. Investigation and resolution** — The case fully documented and closed: root cause identified, evidence (the raw PAM log entry) attached, resolved as a confirmed True Positive with no impact. Note `Created by: wazuh-integration` — this entire case was opened automatically, not by a human analyst.
![Resolved case in TheHive](screenshots/06-case-resolution.png)



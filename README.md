
#  SOC Analysis of an OpenSSH Brute-Force Campaign



##  Case Summary
- **Objective:** My goal was to conduct a full-cycle security investigation on a set of OpenSSH server logs. I aimed to identify the nature of a suspected attack, pinpoint the adversary's TTPs, and operationalize my findings by building a real-time monitoring and alerting solution in Splunk.
- **Scope:** The analysis focused on a dataset of 2,000 log events from a single Linux server's OpenSSH service.
- **Tools Used:** Splunk Cloud, Splunk Processing Language (SPL).
- **Outcome:** I successfully dissected a targeted brute-force attack originating from a single malicious IP. I then built a comprehensive SOC dashboard and a series of automated alerts to shift the security posture from reactive investigation to proactive defense.



##  Tools & Environment
| Tool | Purpose |
| :--- | :--- |
| **Splunk Cloud** | Centralized log ingestion, analysis, threat hunting, and visualization. |
| **Splunk (SPL)** | The core query language I used to search, filter, and correlate log data to find evidence. |
| **Role-Based Access Control** | Securing the Splunk environment itself with Admin, Power, and User roles. |
| **OS/VM Used** | Linux Server (Data Source) / Windows 11 (Analysis Workstation) |



##  Case Background
I was tasked with simulating a real-world Security Operations Center (SOC) scenario. I started with a raw log file (`OpenSSH.csv`) from a critical Linux server, with the initial intelligence suggesting anomalous login activity. My mission was to act as the primary security analyst: ingest this data into a clean Splunk environment and conduct a thorough investigation to determine if the server was under attack, understand the attacker's methods, and build a sustainable defense.



##  Methodology
My investigation followed a structured, repeatable workflow, moving from initial setup to deep analysis and finally to operationalizing the intelligence.

1.  **Environment Preparation:** I first built a secure, multi-user Splunk Cloud environment, implementing Role-Based Access Control to enforce the principle of least privilege.
2.  **Data Ingestion & Validation:** I onboarded the OpenSSH log data into a dedicated index (`openssh`). I immediately verified the integrity of the ingestion, confirming that all 2,000 events were correctly parsed and searchable using the query `index="openssh"`.
3.  **Threat Hunting:** I began the hunt by querying for high-level indicators of malicious activity. My approach was to start broad (e.g., all failed logins) and then pivot my searches based on the initial findings to uncover more specific details.
4.  **Indicator Correlation:** I correlated findings from different queries to build a complete narrative of the attack. For example, I linked the top attacking IP address to the specific user accounts it was targeting.
5.  **Intelligence Operationalization:** I translated my analytical findings into a practical, forward-looking security solution by creating a SOC dashboard for real-time visibility and a set of high-fidelity alerts for immediate threat notification.



##  Findings & Evidence
My threat hunt quickly uncovered a clear and systematic attack pattern. The attacker's actions were not random; they were deliberate and followed a logical progression.

**Indicators of Compromise (IoCs):**
*   **IP Address:** `183.62.140.253`
*   **Attacker Tactic:** Brute-Force Attack, User Enumeration
*   **High-Value Target:** `root` user account

| Artifact Type | Location / Value | Finding |
| :--- | :--- | :--- |
| **Failed Logins (Brute-Force)** | `Attacker IP: 183.62.140.253` | This single IP was responsible for **286 (55%)** of all failed logins, confirming a targeted and automated attack, not incidental errors. |
| **High-Value Account Targeting** | `Target Username: root` | The 'root' account was attacked **370 times**. This showed the attacker’s ultimate goal was to gain complete, privileged control of the system. |
| **Reconnaissance (User Enum)** | `Log Message: "invalid user"` | I found **135 login attempts** against non-existent users from the same IP. This proved the attacker was actively trying to map out valid usernames. |



##  Logs
Below is a sample of the SPL queries I used to uncover the attacker's actions. These queries formed the backbone of my investigation and were later used to power the dashboard panels and alerts.

*Query to identify the top attacking IP addresses:*
```splunk
source="OpenSSH.csv" index="openssh" "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| sort -count
```

*Query to detect user enumeration activity:*
```splunk
source="OpenSSH.csv" index="openssh" "Failed password" "invalid user"
```





## Conclusion
My investigation proved that the Linux server was the target of a sustained brute-force campaign from the IP address `183.62.140.253`. The attacker systematically attempted to enumerate valid user accounts before focusing their efforts on compromising the high-privilege 'root' account.

**Impact:** A successful compromise of the 'root' account would have been a critical security incident, granting the attacker unrestricted access to modify the system, exfiltrate sensitive data, or use the server as a launchpad for further attacks across the network.

**Recommendations:**
1.  **Immediate Action:** Block the offending IP address `183.62.140.253` at the network firewall.
2.  **Automated Defense:** Deploy an automated intrusion prevention tool like `fail2ban` on the server to block brute-forcing IPs in real time.
3.  **Architectural Hardening:** The highest priority should be disabling password authentication for SSH and migrating to **public key authentication**, which would completely mitigate this type of threat.
4.  **Continuous Monitoring:** Adopt the Splunk dashboard and alerts I created as a standard operational tool for the SOC, ensuring ongoing visibility into SSH security.



##  Lessons Learned / Reflection
This project was an excellent exercise in demonstrating the true power of a SIEM. The key takeaway for me was the flow from raw data to operational intelligence. Anyone can find a single bad IP in a log file, but the real value of a security analyst is in contextualizing that finding, understanding the *story* of the attack, and then building a robust, automated system to defend against it in the future.

Technically, it reinforced how crucial SPL commands like `stats`, `rex`, and `sort` are for transforming thousands of noisy events into a single, clear picture of an attack. If I were to do this again, I would enrich the data further by integrating an IP reputation threat intelligence feed to automatically flag known malicious IPs upon ingestion.





#Splunk #SOC #Cybersecurity #ThreatHunting #IncidentResponse #DFIR #BlueTeam #SecurityMonitoring

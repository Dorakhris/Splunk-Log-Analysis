# Splunk SOC Simulation: Investigating an OpenSSH Brute-Force Attack

## Executive Summary

This report details a comprehensive security investigation into OpenSSH server logs using Splunk Cloud. The analysis successfully identified and dissected a multi-stage attack, providing a clear demonstration of an end-to-end Security Operations Center (SOC) workflow.

The investigation uncovered a targeted brute-force campaign from a single malicious IP, systematic user enumeration, and a high-priority attempt to compromise the 'root' account. In response, I developed a suite of actionable intelligence tools, including a real-time monitoring dashboard and automated alerts, to transition the security posture from reactive to proactive.

**This case study highlights my proficiency in transforming raw log data into a robust and repeatable security monitoring capability.**

*   **Tools & Technologies:** Splunk Cloud, Splunk Search Processing Language (SPL), Linux (OpenSSH), Role-Based Access Control (RBAC).

---

## The Investigation & Analysis Process

My approach followed a structured, three-phase process common in real-world security operations.

### Phase 1: Environment Setup and Data Ingestion
Before analysis could begin, a secure and reliable data pipeline was established.

*   **Secure Environment:** Configured a multi-user Splunk environment with Role-Based Access Control (Admin, Power, User roles) to enforce the principle of least privilege.
*   **Data Onboarding:** Successfully ingested the OpenSSH log dataset into a dedicated Splunk Cloud index.
*   **Ingestion Verification:** Confirmed that all 2,000 log events were correctly indexed and parsed using a baseline SPL query (`index="openssh"`), ensuring data integrity for the investigation.

### Phase 2: Threat Hunting and Key Findings
With the data onboarded, I began the threat hunting process by querying for patterns of malicious activity.

#### Finding 1: Detection of a Sustained Brute-Force Attack
A query for failed login attempts immediately revealed a high volume of suspicious activity.

```splunk
source="OpenSSH.csv" index="openssh" "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| sort -count
```
*   **Result:** A total of **520 failed login attempts** were recorded. The IP address `183.62.140.253` was responsible for **286 (55%)** of these failures.
*   **Implication:** This disproportionate volume indicates a determined, automated attack from a single source, not random login errors.

#### Finding 2: Attempted Compromise of a High-Value Target
I then investigated which user accounts were being targeted to understand the attacker's objective.

```splunk
source="OpenSSH.csv" index="openssh" "Failed password" "root"
```
*   **Result:** The **'root'** user was the target of **370 failed login attempts**.
*   **Implication:** Targeting the 'root' user signifies a high-stakes attempt to gain complete, unrestricted control over the system, which would be a critical security breach.

#### Finding 3: Identification of Systematic User Enumeration
Further analysis revealed attempts to log in with non-existent accounts, a common reconnaissance technique.

```splunk
source="OpenSSH.csv" index="openssh" "Failed password" "invalid user"
```
*   **Result:** A total of **135 failed attempts** were against invalid users.
*   **Implication:** This confirms the attacker was not just targeting known accounts but was actively trying to discover valid usernames for future, more focused attacks.

---

### Phase 3: Operationalizing Intelligence — From Findings to Defense
Identifying threats is critical, but creating sustainable defenses is the ultimate goal. I translated my findings into a repeatable monitoring solution.

#### Comprehensive SOC Dashboard
I designed and built a Splunk dashboard to provide the security team with at-a-glance, real-time visibility into the SSH environment.

**Key Dashboard Panels:**
*   Top 10 IPs by Failed Logins
*   Real-time Feed of Accepted Logins
*   Count of User Enumeration Attempts over Time
*   Authentication Failure Trends

#### Proactive Alerting Strategy
To enable rapid response, I configured automated alerts that trigger on high-confidence indicators of an attack, reducing detection time from hours to seconds.

| Alert Name | Trigger Condition | Purpose |
| :--- | :--- | :--- |
| **Brute-Force Attempt Detected** | More than 20 failed logins from a single IP in 5 minutes. | Immediately notify the team of a concentrated password-guessing attack. |
| **Suspicious IP Activity** | Any login (successful or failed) from a known malicious IP. | Leverage threat intelligence to stop known attackers at the door. |
| **Potential User Enumeration** | More than 5 "invalid user" errors from a single IP in 10 minutes. | Detect attacker reconnaissance before a targeted attack begins. |

---

## Strategic Recommendations & Business Impact

Based on the investigation, I formulated the following recommendations to harden the security posture and mitigate business risk:

1.  **Immediate Containment:** Block the top offending IP address (`183.62.140.253`) at the network firewall to instantly stop the ongoing attack.
2.  **Automated Defense:** Implement a tool like `fail2ban` on the server. This automates the blocking of brute-force IPs, reducing the manual workload on the SOC team and improving response time.
3.  **Architectural Hardening:** Prioritize the migration from password-based authentication to **public key authentication**. This would eliminate the risk of password-guessing attacks entirely, representing a significant improvement in security.
4.  **Continuous Monitoring:** Formally adopt the new Splunk dashboards and alerts as part of the standard daily operating procedure for the SOC team.

By implementing these changes, the organization can significantly reduce its attack surface and enhance its ability to detect and respond to future threats.

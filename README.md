# Splunk-Based Threat Analysis of OpenSSH Logs


## Overview

This project showcases a comprehensive security analysis of OpenSSH server logs using **Splunk Cloud**. The objective was to simulate a real-world Security Operations Center (SOC) investigation, moving from initial data ingestion to proactive threat detection, detailed analysis, and the creation of actionable security intelligence.

The analysis uncovered a targeted brute-force attack, systematic user enumeration, and identified several high-risk Indicators of Compromise (IOCs). The project culminates in the development of real-time monitoring dashboards and automated alerts, demonstrating a full-cycle security monitoring workflow.

This project highlights my hands-on skills in SIEM implementation, log analysis, threat detection, and security automation`

## The Investigation Workflow

### 1. Environment Setup & Data Ingestion

- **User Management:** Established a secure multi-user environment by creating role-based accounts (Admin, Power, User) for the SOC team, enforcing a "least privilege" principle.
- **Data Onboarding:** Successfully ingested OpenSSH logs into Splunk Cloud. 
- **Verification:** Confirmed successful ingestion and parsing with a baseline SPL query, ensuring all 2,000 events were indexed and ready for analysis.

### 2. Threat Hunting & Analysis

My analysis focused on identifying patterns of malicious behavior within the log data.

#### Finding 1: Targeted Brute-Force Attack

A high volume of **520 failed login attempts** was detected. I used SPL to investigate further:

```splunk
source="OpenSSH.csv" index="openssh" "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| sort -count
```

- **Result:** The IP address `183.62.140.253` was responsible for **286 failed attempts**, indicating an automated attack.



#### Finding 2: High-Value Target Compromise Attempt

I narrowed the search to identify specific targets.

```splunk
source="OpenSSH.csv" index="openssh" "Failed password" "root"
```

- **Result:** **370 attempts** specifically targeted the **'root'** user, highlighting a clear intent to gain privileged access.



#### Finding 3: Systematic User Enumeration

The logs also showed attempts against non-existent users, a classic enumeration tactic.

```splunk
source="OpenSSH.csv" index="openssh" "Failed password" "invalid user"
```

- **Result:** **135 failed attempts** were against invalid users, confirming that attackers were actively trying to discover valid account names.



### 3. Operationalizing Intelligence: Dashboards & Alerts

Identifying threats is only half the battle. A key outcome of this project was to build a sustainable monitoring solution.

#### Security Dashboards

I created a series of dashboards to provide the SOC team with at-a-glance visibility into SSH security posture. Key panels include:
- Top IPs by Failed Logins
- Top IPs by Authentication Failures
- Real-time `Accepted Password` Events (to immediately spot potential breaches)
- User Enumeration Attempts



#### Proactive Alerts

To enable rapid response, I configured several automated alerts that trigger on high-fidelity indicators of an attack.

- **Authentication Failure Spike:** Triggers if the number of authentication failures exceeds a set threshold in a short time frame.
- **Login from Suspicious IP:** Triggers on any activity from IPs with known bad reputations.
- **Enumeration Detected:** Triggers when a single IP generates multiple "invalid user" errors.



---

## Recommendations & Security Posture Improvements

Based on the investigation, I formulated several key recommendations to present to stakeholders:

1.  **Immediate Action:** Block the top offending IP addresses at the perimeter firewall.
2.  **Preventive Control:** Deploy `fail2ban` to automatically block IPs that exhibit brute-force behavior.
3.  **Authentication Hardening:** Prioritize the transition from password-based authentication to more secure **key-based authentication** to mitigate the risk of password-guessing attacks.
4.  **Continuous Monitoring:** Continue leveraging the newly created Splunk dashboards and alerts for proactive threat detection and response.

---

## Conclusion

This project demonstrates my capability to function as a proactive and detail-oriented SOC analyst. I successfully navigated the entire threat analysis lifecycle: from raw data to actionable intelligence, and finally to automated monitoring.

This hands-on experience with Splunk, combined with a strong understanding of attacker techniques and defensive strategies, makes me a unique and valuable candidate for a Security Operations role.

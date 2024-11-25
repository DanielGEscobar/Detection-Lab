# Detection-Lab

## Objective

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used


- SIEM Platforms:
Splunk (free tier) or ELK Stack (Elasticsearch, Logstash, Kibana).
Log Forwarding Tools:
Splunk Universal Forwarder, Filebeat.
Log Sources:
Windows Event Logs, Linux Syslog, Apache/Nginx Logs, Firewall Logs.
Attack Simulation Tools:
Metasploit, Nmap, Hydra, or Scapy.
Virtualization:
VirtualBox or VMware to set up the test environment.
Network Traffic Tools:
Wireshark, Tcpreplay.

## Steps
Steps in the Project

#Network Diagram

1. Define the Environment
Objective: Build a lab environment to simulate real-world network traffic and security scenarios.
Setup:
Install a SIEM tool (e.g., Splunk or ELK) on a VM or local machine.
Set up VMs for log sources:
Windows 10/Server for event logs.
Linux server for syslog and application logs.
pfSense for firewall logs.

2. Configure Log Sources
Windows Event Logs:
Enable logging for user activity and security events.
Install Splunk Universal Forwarder or Filebeat for log forwarding.
Linux Syslog:
Enable /var/log monitoring (e.g., auth.log, syslog).
Configure rsyslog to send logs to the SIEM.
Application Logs:
Set up a web server (e.g., Apache or Nginx) to generate access and error logs.
Firewall Logs:
Enable logging on pfSense and forward logs to the SIEM.

3. Ingest Logs into the SIEM
Configure data ingestion pipelines in the SIEM:
For Splunk:
Define inputs for each log source.
Configure indexers for log categorization.
For ELK:
Use Logstash to parse and normalize log data.
Store processed logs in Elasticsearch.

4. Analyze the Logs
Queries:
Create searches to detect suspicious activities:
Failed login attempts (Windows and Linux).
High HTTP error rates from the web server.
Unusual outbound traffic from pfSense logs.
Dashboards:
Design visualizations for key metrics:
User login trends.
Top IPs by traffic volume.
Frequency of error codes from web servers.

5. Simulate Security Incidents
Brute-Force Attack:
Use tools like Hydra to simulate brute-force login attempts on SSH or HTTP.
Port Scanning:
Use Nmap to scan open ports on a VM.
Suspicious File Uploads:
Simulate uploads of malicious files to the web server.
Data Exfiltration:
Generate large volumes of outbound traffic.

6. Detect and Respond to Incidents
Write correlation rules:
Example: Alert if >5 failed logins occur within 10 minutes.
Configure alerts for:
Traffic spikes (potential DDoS attack).
Access from blacklisted IPs.
Changes in critical files or configurations.

7. Document and Visualize
Architecture Diagram:
Show the flow of logs from sources to the SIEM.
Dashboards:
Include screenshots of visualizations for incident trends and KPIs.
Incident Reports:
Document simulated incidents, detection methods, and remediation steps.

8. Deliverables
Portfolio Assets:
A comprehensive report (PDF/Word):
Overview of the environment and objectives.
Queries and dashboards created.
Security incidents simulated and detected.
Screenshots of the SIEM setup, queries, and alerts.
(Optional) A video walkthrough of the project.

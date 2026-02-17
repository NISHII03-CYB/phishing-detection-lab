# phishing-detection-lab

Phishing Email Detection & Investigation Using Splunk SIEM


Name : Dehiwattage Kavindu Nishitha Fernando

Role : SOC Analyst (Lab Project)

Date : 16/02/2026

This project demonstrates the simulation, detection, and investigation of phishing email activity using Splunk SIEM. A structured email log dataset was created to simulate phishing indicators such as typosquatted domains, IP-based URLs, and urgent subject lines. Detection logic was developed using SPL to identify suspicious email artifacts. The lab replicates a SOC Tier 1 workflow for detecting and investigating phishing attempts aligned with MITRE ATT&CK technique T1566 (Phishing).

________________________________________

Project Objective

The objective of this lab was to:

•	Simulate phishing email log data

•	Ingest structured email logs into Splunk

•	Identify phishing indicators

•	Build detection logic using SPL

•	Configure automated alerting

•	Perform SOC-style investigation workflow

________________________________________

Environment Setup

Component	Description

SIEM Platform	Splunk Enterprise

Operating System	Windows

Log Type	Simulated Email Logs (CSV format)

Index	email_logs
________________________________________

Phishing Simulation Data

A structured CSV file was created containing simulated email log entries.

Example:https://github.com/NISHII03-CYB/phishing-detection-lab/blob/main/Screenshot%202026-02-16%20211802.png
 


________________________________________

Phishing Indicators Identified

The simulated phishing emails contained the following indicators:

•	Typosquatting domains (micr0soft, paypa1)

•	IP-based URLs instead of domain names

•	Urgent language in subject lines

•	Impersonation of legitimate organizations

These are common phishing characteristics.

________________________________________

Detection Engineering

*Detect IP-Based URLs

index=email_logs

| where match(url, "http://\d+\.\d+\.\d+\.\d+")

Purpose:

Detects emails containing direct IP address URLs.

________________________________________

*Detect Suspicious Sender Domains

index=email_logs

| where like(sender,"%micr0soft%") OR like(sender,"%paypa1%")

Purpose:

Identifies typosquatting attempts.

________________________________________

*Detect Urgent Subject Language

index=email_logs

| search "Urgent" OR "Verify" OR "Account"

Purpose:

Flags social engineering patterns.

________________________________________

*Combined Detection Logic

index=email_logs

| eval ip_url=if(match(url,"http://\d+\.\d+\.\d+\.\d+"),1,0)

| eval suspicious_sender=if(like(sender,"%micr0soft%") OR like(sender,"%paypa1%"),1,0)

| eval urgent_language=if(match(subject,"Urgent|Verify"),1,0)

| where ip_url=1 OR suspicious_sender=1 OR urgent_language=1

This query correlates multiple phishing indicators.

________________________________________

Alert Configuration

The detection query was converted into a scheduled alert:

•	Cron schedule: */5 * * * *

•	Time range: Last 5 minutes

•	Trigger condition: Number of Results > 0

•	Trigger type: Once

•	Action: Add to Triggered Alerts

This simulates continuous phishing monitoring.

________________________________________

Investigation Workflow

Upon alert trigger, the following steps were performed:

1.	Extracted sender domain

2.	Analyzed domain for typosquatting

3.	Identified IP-based URLs

4.	Scoped campaign impact by searching similar senders

5.	Determined risk severity

6.	Recommended blocking sender and URL


________________________________________

Findings

The detection successfully identified:

•	Suspicious sender domains

•	IP-based phishing URLs

•	Social engineering language

•	Multiple phishing indicators in a single event

The logic effectively simulated phishing detection in a SOC environment.

________________________________________

Limitations

•	Dataset was simulated

•	No live email gateway integration

•	No sandbox URL analysis performed

•	No user click tracking implemented

________________________________________

Conclusion

This lab successfully demonstrated:

•	Phishing artifact identification

•	Indicator-based detection engineering

•	SPL query development

•	Alert configuration

•	SOC investigation workflow

The project reflects practical SOC Tier 1 responsibilities for detecting and investigating phishing threats.


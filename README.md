Title: SAP Audit Log Monitoring in Splunk (Simulated SIEM Lab)

Project Overview:

This lab simulates monitoring SAP ERP audit logs in Splunk, focusing on
security-relevant events like logins, role changes, financial postings,
vendor creation, and emergency (firefighter) access.

The goal is to show how a security team could:
a) onboard SAp audit logs into a SIEM
b) Detect suspicious or malicious activity
c) Visualize SAP security posture on a single dashboard

Lab Architecture:

Synthetic SAP application logs (`sap_audit.log`)
Splunk Enterprise (local) as the SIEM
Custom sourcetype: `sap:audit:log`
Index: `sap_audit` (or `main` in simple setups)
Saved searches and a “SAP Security Overview” dashboard

Data Flow:

SAP (simulated) -> 'sap_audit.log' -> Splunk upload -> index ('sap_audit') -> searches & dashboards

Data:

Log Source: 'data/sap_audit.log'

Generated using: 'scripts/generate_sap_logs.py'


The dataset contains both:
Normal business activity
Injected attack/fraud scenarios:
Brute-force login from external IP
High-risk role assignment (SAP_ALL, FI_SUPER, BASIS_ADMIN)
High-value postings
Vendor creation + large posting in short time
Off-hours firefighter access

How to run the lab:

run    python3 scripts/generate_sap_logs.py


Detection cases:

for brute force:
index=main sourcetype="sap:audit:log" event_type="LOGIN_FAILED"
| stats count AS failed_attempts BY user, source_ip
| where failed_attempts > 10

for high-risk role assignment:
index=main sourcetype="sap:audit:log" event_type="CHANGE_ROLE"
| search new_role=SAP_ALL OR new_role=FI_SUPER OR new_role=BASIS_ADMIN
| table _time user target_user new_role source_ip severity message

for high-value financial posting:
index=main sourcetype="sap:audit:log" event_type="POST_DOCUMENT"
| eval amount_num = tonumber(amount)
| where amount_num > 50000
| table _time user vendor_id amount currency tcode source_ip severity message

for vendor fraud chain:
index=main sourcetype="sap:audit:log" (event_type="CREATE_VENDOR" OR event_type="POST_DOCUMENT")
| eval amount_num = tonumber(amount)
| stats 
    min(_time) AS first_seen
    max(_time) AS last_seen
    values(event_type) AS event_types
    values(user) AS users_involved
    values(amount) AS amounts
    count AS event_count
  BY vendor_id
| eval time_diff = last_seen - first_seen
| where mvcount(event_types) > 1 AND time_diff < 3600
| table vendor_id first_seen last_seen time_diff users_involved amounts

for off hour emergency:
index=main sourcetype="sap:audit:log" event_type="FIREFIGHTER_LOGIN"
| eval hour = tonumber(strftime(_time, "%H"))
| where hour < 6 OR hour > 20
| table _time user source_ip hour severity message



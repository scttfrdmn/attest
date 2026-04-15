# Meridian Research University
# Incident Response Plan — Version 4.1
# Effective: February 2024 | Next Review: February 2025
# Approved: Janet Park, CISO

---

## 1. Purpose

This plan establishes MRU's capability to prepare for, detect, respond to, and recover
from information security incidents. It documents roles, procedures, communication
chains, and evidence preservation requirements.

---

## 2. Incident Classification

| Severity | Definition | Response Time |
|----------|-----------|---------------|
| P1 — Critical | Active breach, ransomware, PHI exposure, CUI spill | Immediate (< 1 hour) |
| P2 — High | Compromised credentials, malware detected | 2 hours |
| P3 — Medium | Policy violation, unauthorized access attempt | 24 hours |
| P4 — Low | Suspicious activity, failed login patterns | 72 hours |

---

## 3. Incident Response Team

| Role | Primary | Backup |
|------|---------|--------|
| Incident Commander | Janet Park (CISO) | David Kim (Deputy CISO) |
| Technical Lead | Aisha Okonkwo (Sr. Security Engineer) | Marcus Webb (Cloud Security) |
| Communications | Lisa Torres (General Counsel) | Mark Chen (PR) |
| Research Liaison | Dr. Robert Nwachukwu (VP Research) | Per-incident PI |

**Emergency contacts**:
- IT Security 24/7: (555) 867-5309
- CISO mobile: (555) 293-4471
- AWS Business Support: [via AWS Console Support Case]

---

## 4. Preparation

### 4.1 Prevention measures in place

- AWS CloudTrail enabled across all accounts (7-year retention for HIPAA accounts)
- Amazon GuardDuty enabled organization-wide
- AWS Security Hub aggregating findings from all accounts
- Multi-factor authentication required for all privileged access
- Quarterly access reviews for all Sensitive/Restricted environments

### 4.2 Communication channels

- Incident Slack channel: #security-incidents (restricted access)
- Encrypted email: incidents@mru.edu (PGP key on security.mru.edu)
- War room: Zoom (link in #security-incidents channel pin)

---

## 5. Detection and Analysis

### 5.1 Detection sources

Incidents are detected through:
- Amazon GuardDuty threat detection findings
- AWS Security Hub aggregated findings
- User reports via security.mru.edu/report
- CloudTrail anomaly analysis (weekly review)
- External notifications (FBI, HHS, AWS security team)

### 5.2 Initial analysis checklist

Upon receiving an alert or report:

- [ ] Identify affected systems and accounts (AWS account IDs, resource ARNs)
- [ ] Determine data classification of affected resources (PHI? CUI? FERPA?)
- [ ] Assign severity level (P1-P4)
- [ ] Notify Incident Commander within 15 minutes if P1 or P2
- [ ] Open incident ticket in ServiceNow
- [ ] Begin timeline documentation

---

## 6. Containment

### 6.1 Short-term containment

**For compromised AWS credentials**:
1. Immediately disable the IAM user or invalidate STS tokens
2. Rotate any credentials that may have been exposed
3. Enable AWS CloudTrail Data Events on affected S3 buckets
4. Request AWS CloudTrail Lake query for the affected credential ARN

**For compromised EC2 instances**:
1. Take EBS snapshot for forensics before any action
2. Isolate instance to a quarantine security group (deny all ingress/egress)
3. Do not terminate — preserve for forensic analysis
4. Notify PI if research workloads are impacted

**For ransomware**:
1. Immediately isolate affected systems (quarantine security group)
2. Do NOT pay any ransom without CISO and legal approval
3. Notify FBI Cyber Division (IC3.gov) within 24 hours
4. Begin recovery planning from last known-good backup

### 6.2 PHI breach containment

If PHI exposure is suspected or confirmed:
1. Immediately notify CISO — HIPAA Breach Notification Rule may apply
2. Document minimum necessary information: what PHI, how many individuals, what exposure
3. Do not communicate about the breach externally without Legal and CISO approval
4. Preserve all systems involved — do not delete logs or modify configurations

---

## 7. Eradication and Recovery

### 7.1 Eradication

- Remove malware using AWS GuardDuty findings and manual analysis
- Patch vulnerabilities identified as attack vectors
- Rotate all credentials that may have been exposed
- Revoke and reissue certificates if involved

### 7.2 Recovery

- Restore affected systems from last known-good backup or AMI
- Verify integrity of restored data using checksums
- Re-enable monitoring and alerting before returning systems to production
- Confirm with PI that research workloads are operational
- Monitor closely for 72 hours post-recovery

---

## 8. Post-Incident Activities

### 8.1 Documentation requirements

All P1 and P2 incidents require a post-incident report within 14 days:
- Timeline of events (detection to resolution)
- Root cause analysis
- Impact assessment (data affected, systems affected, duration)
- Remediation steps taken
- Recommendations to prevent recurrence

### 8.2 Regulatory notifications

| Regulation | Trigger | Deadline | Notify |
|-----------|---------|----------|--------|
| HIPAA | PHI breach > 0 individuals | 60 days | HHS, affected individuals |
| HIPAA | PHI breach > 500 individuals | 60 days | HHS, media, individuals |
| DoD | CUI spill | 1 hour (IT Sec), 24 hours (contract officer) | Contracting Officer |
| FERPA | Education records breach | Immediate | CISO + Legal |

### 8.3 Lessons learned

Within 30 days of incident closure:
- Update this plan if procedures were inadequate
- Update detective controls if detection was delayed
- Schedule additional training if human error was a factor
- Submit findings to annual risk assessment process

---

## 9. Testing

This plan is tested annually via tabletop exercise. Scenarios rotate through:
- Year 1: Compromised researcher credentials, PHI exposure
- Year 2: Ransomware on research compute, CUI handling
- Year 3: Insider threat, data exfiltration

Most recent test: September 2025 — Scenario: Phishing attack on PI, lateral movement
to genomics data. Findings: Detection time acceptable (47 min); containment procedures
need update for EKS workloads. IRP v4.1 incorporates those updates.

---

*Meridian Research University — Office of Information Technology*
*Document owner: Janet Park, CISO | itsecurity@mru.edu*

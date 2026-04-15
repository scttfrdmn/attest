# Meridian Research University
# Information Security Policy
# Version 3.2 | Effective: March 1, 2024 | Next Review: March 1, 2025
# Approved: Janet Park, CISO | Office of Information Technology

---

## 1. Purpose and Scope

This policy establishes the information security requirements for all faculty, staff,
students, and contractors accessing Meridian Research University (MRU) information
systems, including cloud-hosted research environments. It applies to all data
classifications handled by MRU, including Protected Health Information (PHI),
Controlled Unclassified Information (CUI), and student educational records (FERPA).

---

## 2. Roles and Responsibilities

**Chief Information Security Officer (CISO)**: Responsible for the information security
program, policy enforcement, and annual review.

**Principal Investigators (PIs)**: Responsible for data classification, access control
within their labs, and ensuring lab members complete required training.

**IT Security Team**: Responsible for technical controls, incident response, and
security monitoring.

**Lab Members (researchers, students, staff)**: Responsible for following this policy
and all applicable data handling procedures.

---

## 3. Data Classification

MRU classifies research data into four categories:

| Class | Examples | Controls |
|-------|----------|----------|
| Public | Published papers, course materials | No restrictions |
| Internal | Administrative records | MRU network or VPN required |
| Sensitive | PHI, FERPA, CUI | Encrypted storage, access controls, training required |
| Restricted | Export-controlled, classified-adjacent | Additional approval, CMMC compliance |

All data must be tagged with its classification. Research involving human subjects
data automatically requires Sensitive classification pending IRB protocol review.

---

## 4. Risk Management

### 4.1 Annual Risk Assessment

MRU conducts an annual information security risk assessment covering all research
environments, cloud infrastructure, and data handling procedures. The assessment:

- Identifies threats to research data confidentiality, integrity, and availability
- Evaluates existing controls against identified threats
- Produces a Plan of Action & Milestones (POA&M) for identified gaps
- Is reviewed and approved by the CISO and presented to the Research Computing
  Advisory Committee

The most recent risk assessment was completed February 2026. Next assessment: February 2027.

### 4.2 Risk Management Measures

Identified risks are categorized as Critical, High, Medium, or Low. Response timelines:

- Critical: Remediation within 7 days
- High: Remediation within 30 days
- Medium: Remediation within 90 days, documented in POA&M
- Low: Remediation within 180 days or accepted with documentation

### 4.3 Sanction Policy

Violations of this policy are subject to sanctions consistent with MRU's Code of
Conduct, which may include: written warning, suspension of system access, termination
of employment or enrollment, and referral for legal action.

---

## 5. Access Control

### 5.1 Principle of Least Privilege

All access to MRU information systems must follow the principle of least privilege.
Users are granted only the access necessary to perform their assigned functions.
Access requests require PI approval and IT Security review for Sensitive data.

### 5.2 Access Provisioning and Review

- New access requests: submitted via the IT Service Portal with PI signature
- Quarterly access reviews: IT Security reviews all active accounts quarterly
- Termination: access revoked within 24 hours of departure (same day for involuntary)
- Annual recertification: PIs certify continued need for all lab member access annually

### 5.3 Multi-Factor Authentication

Multi-factor authentication (MFA) is required for:
- All access to MRU administrative systems
- All access to cloud environments handling Sensitive or Restricted data
- Remote access via VPN
- All privileged accounts (administrator, root)

Hardware security keys (YubiKey) are required for all research accounts with CUI access.

### 5.4 Password Requirements

- Minimum 16 characters for standard accounts
- Minimum 20 characters for privileged accounts
- No password reuse for 24 generations
- Passwords must not contain dictionary words, usernames, or personal information

---

## 6. CUI Handling

### 6.1 Definition

CUI is information the Government creates or possesses that requires safeguarding
per law, regulation, or Government-wide policy, but is not classified. Examples in
MRU research: export-controlled research data, DoD contract deliverables, law
enforcement sensitive information.

### 6.2 Handling Requirements

- CUI must only be stored in systems approved for CUI handling (AWS enclave accounts)
- CUI must not be transmitted via unencrypted email or stored in personal cloud services
- CUI must be marked per NARA guidance when shared
- CUI handling requires completion of the CUI Fundamentals training (see Section 8)

### 6.3 CUI Spills

A CUI spill occurs when CUI is transmitted to a system not authorized to receive it.
CUI spills must be reported to IT Security (itsecurity@mru.edu) within 1 hour of
discovery. IT Security will notify the DoD contract officer within 24 hours.

---

## 7. Incident Response

### 7.1 Incident Definition

An information security incident is any event that compromises the confidentiality,
integrity, or availability of MRU information assets. This includes:
- Unauthorized access to systems or data
- Malware infection or ransomware
- Data breach or exposure of PHI/CUI
- Denial-of-service attacks against research infrastructure
- Insider threat activity

### 7.2 Reporting

All suspected incidents must be reported immediately to:
- **IT Security hotline**: (555) 867-5309 (24/7)
- **Email**: incidents@mru.edu
- **Portal**: security.mru.edu/report

Do not attempt to investigate or remediate incidents independently. Preserve all
logs and system state pending IT Security guidance.

### 7.3 Response Procedures

MRU's Incident Response Plan (IRP v4.1, February 2024) governs the response process:

1. **Detection and reporting** (within 1 hour)
2. **Initial assessment** by IT Security (within 2 hours)
3. **Containment** — isolate affected systems to prevent spread
4. **Eradication** — remove malware, close vulnerabilities
5. **Recovery** — restore from backup, verify integrity
6. **Post-incident review** — root cause analysis within 14 days

For PHI breaches, HIPAA Breach Notification Rule requirements apply (60-day notification
to HHS, individual notification within 60 days, media notice if >500 individuals affected).

### 7.4 IR Testing

The incident response capability is tested annually via tabletop exercise. The most
recent exercise was conducted September 2025. Findings are incorporated into the IRP
as part of the annual review cycle.

---

## 8. Security Training

### 8.1 General Security Awareness Training

All MRU faculty, staff, and graduate students must complete the annual Security
Awareness Training module in Canvas (MRU LMS). Training covers:
- Password hygiene and phishing recognition
- Acceptable use of MRU systems
- Data classification and handling
- Incident reporting

Training must be completed within 30 days of joining MRU and renewed annually.
Completion is tracked in Canvas and reported to department heads quarterly.

### 8.2 Role-Based Training Requirements

Additional training is required based on data access:

| Training | Required for | Platform | Renewal |
|----------|-------------|----------|---------|
| HIPAA Privacy and Security | All PHI handlers | CITI Program | Annual |
| CUI Fundamentals | All CUI handlers | CITI Program | Annual |
| FERPA Basics | All student data handlers | Canvas | Annual |
| Research Data Security | All lab PIs | Canvas | Annual |

### 8.3 Training Records

Training completion is maintained in:
- MRU Canvas LMS (completion certificates, dates)
- CITI Program (external certificates)
- Exported quarterly to IT Security training database

Current training completion rate (as of March 2026):
- Security Awareness: 94% of required personnel
- HIPAA Training: 89% of PHI handlers
- CUI Fundamentals: 67% of CUI handlers ← gap identified, remediation in progress

---

## 9. Media and Device Controls

All media and devices used to process Sensitive or Restricted data must be:
- Encrypted using AES-256 or equivalent
- Approved and registered with IT Security
- Returned or certified destroyed upon departure

Removable media (USB drives, external hard drives) are prohibited in CUI environments
except for documented operational necessity with CISO approval.

---

## 10. Audit and Monitoring

MRU maintains audit logs of all access to Sensitive and Restricted data. Logs are:
- Retained for a minimum of 3 years (7 years for HIPAA-covered systems)
- Reviewed weekly by IT Security for anomalous access patterns
- Available to authorized investigators upon legal request

The IT Security team conducts periodic security assessments to verify control
effectiveness. Findings are incorporated into the annual risk assessment.

---

## 11. Policy Review

This policy is reviewed annually or upon significant changes to the regulatory
environment, MRU's technology environment, or lessons learned from security incidents.

| Version | Date | Changes |
|---------|------|---------|
| 3.2 | 2024-03-01 | Added CUI handling section; updated training table |
| 3.1 | 2023-03-01 | Updated MFA requirements; added hardware key requirement |
| 3.0 | 2022-06-01 | Comprehensive rewrite for NIST CSF alignment |

---

*Meridian Research University — Office of Information Technology*
*Questions: itsecurity@mru.edu | Document owner: Janet Park, CISO*

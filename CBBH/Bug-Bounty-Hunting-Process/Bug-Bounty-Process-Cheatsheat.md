# Bug Bounty Commands & Technical Details Cheat Sheet

## CVSS 3.1 Calculator Metrics Quick Reference

### Attack Vector Values
- **Network (N)** - Remotely exploitable through network
- **Adjacent (A)** - Same physical/logical network required
- **Local (L)** - Local system access required
- **Physical (P)** - Physical interaction required

### Attack Complexity Values
- **Low (L)** - No special preparations needed
- **High (H)** - Special preparations required

### Privileges Required Values
- **None (N)** - No special access needed
- **Low (L)** - Standard user privileges
- **High (H)** - Admin-level privileges

### User Interaction Values
- **None (N)** - No user interaction required
- **Required (R)** - User action needed

### Scope Values
- **Unchanged (U)** - Affects only vulnerable component
- **Changed (C)** - Can affect other components

### Impact Values (Confidentiality/Integrity/Availability)
- **None (N)** - No impact
- **Low (L)** - Some loss of CIA
- **High (H)** - Total/severe loss of CIA

## Technical Identifiers

### Common File Signatures
- **Java Serialized Objects**: Base64 encoded data starting with `rO0`

### Example Payloads from Document
- **XSS Filename Payload**: `"><svg onload = alert(document.cookie)>.docx`

## CVSS Score Examples from Document

### Critical Vulnerability (9.8)
- **Cisco ASA Buffer Overflow**: Network/Low/None/None/Unchanged/High/High/High
- **IBM WebSphere RCE**: Network/Low/None/None/Unchanged/High/High/High

### Medium Vulnerability (5.5)
- **Stored XSS in Admin Panel**: Network/Low/High/None/Changed/Low/Low/None

## Report Structure Template

```
Title: [Vulnerability Type] in [Location]
CWE: [CWE-Number]: [CWE Description]
CVSS 3.1 Score: [Score] ([Severity Level])
Description: [Technical description of the vulnerability]
Impact: [Business and technical impact]
POC: [Step-by-step reproduction steps]
CVSS Score Breakdown: [Detailed metric explanations]
```1

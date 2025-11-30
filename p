

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



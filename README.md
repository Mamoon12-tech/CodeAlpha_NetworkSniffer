# 🔬 NetScope — Basic Network Sniffer
### CodeAlpha Cybersecurity Internship | Task 1

---

## 📌 What This Does

NetScope is a beginner-friendly Python network sniffer that **captures live network packets** and breaks them down into human-readable information — no Wireshark needed.

It shows you:
- 🌐 **Source & Destination IP addresses**
- 🚪 **Ports** (which service the data is going through)
- 📦 **Protocol** (TCP, UDP, ICMP, and more)
- 📄 **Payload preview** (what data is inside the packet)
- 📊 **Session stats** at the end
- 💾 **Auto-saves a log file** of everything captured

---

## 🚀 How to Run

### 1. Save the file
Download `sniffer.py` to your Linux machine or WSL terminal.

### 2. Give it permission
```bash
chmod +x sniffer.py
```

### 3. Run it
```bash
sudo python3 sniffer.py
```

Press `Ctrl+C` to stop — it will print a session summary and save a log file automatically.

---

## ⚙️ Customise It

Inside `sniffer.py`, at the bottom, you can change two settings:

```python
run_sniffer(
    packet_limit=50,      # Capture only 50 packets, then stop
    filter_proto="TCP",   # Show only TCP packets
)
```

| Setting | Options |
|---|---|
| `packet_limit` | Any number (0 = unlimited) |
| `filter_proto` | `"TCP"`, `"UDP"`, `"ICMP"`, `None` (all) |

---

## 📚 Concepts Learned

| Concept | What it means |
|---|---|
| **Raw Socket** | A special socket that captures ALL packets, not just yours |
| **Ethernet Frame** | The outermost wrapper of data on a local network |
| **IPv4 Header** | Contains source/destination IPs and the protocol type |
| **TCP** | Reliable protocol — used by web, email, SSH |
| **UDP** | Fast protocol — used by DNS, video streaming, games |
| **ICMP** | Control messages — used by `ping` |
| **Port** | A numbered "door" — each service has its own (e.g. 443 = HTTPS) |

---

## 🛠️ Requirements

- Python 3.6+
- Linux OS (or WSL on Windows)
- Root/sudo access
- No external libraries needed — uses only Python built-ins!

---

## ⚠️ Legal & Ethical Notice

> This tool is built for **educational purposes only**.  
> Only sniff traffic on **networks you own or have explicit permission to monitor**.  
> Unauthorized packet sniffing is illegal in most jurisdictions.

---

## 👤 Author

**Mamoon**  
Computer Systems Engineering — UET Peshawar  
CodeAlpha Cybersecurity Internship

---

*Built with 💙 and a lot of curious bytes.*

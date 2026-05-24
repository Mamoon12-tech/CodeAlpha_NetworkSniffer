#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         🔬 NetScope — Basic Network Sniffer                      ║
║         CodeAlpha Cybersecurity Internship | Task 1              ║
║         Author  : Mamoon                                         ║
║         Purpose : Capture & Analyze Network Packets              ║
╚══════════════════════════════════════════════════════════════════╝

  What this program does:
  - Listens to live network traffic on your machine
  - Captures packets and breaks them down
  - Shows you: Source IP, Destination IP, Protocol, Port, Payload
  - Saves everything to a log file for later review

  ⚠️  Run with: sudo python3 sniffer.py  (admin rights needed)
"""

# ──────────────────────────────────────────────
#  IMPORTS  —  tools we need to make this work
# ──────────────────────────────────────────────
import socket          # Built-in: raw network access
import struct          # Built-in: unpack binary data (bytes → numbers)
import textwrap        # Built-in: wrap long text nicely
import datetime        # Built-in: timestamps for logs
import os              # Built-in: clear screen, check OS
import sys             # Built-in: exit cleanly

# ──────────────────────────────────────────────
#  COLOUR CODES  —  makes the terminal beautiful
# ──────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

C = Color  # short alias

# ──────────────────────────────────────────────
#  PROTOCOL MAP  —  number → human-readable name
#  (The internet uses numbers to identify protocols)
# ──────────────────────────────────────────────
PROTOCOL_MAP = {
    1:   ("ICMP", C.CYAN),     # Ping packets
    6:   ("TCP",  C.GREEN),    # Reliable data (web, email, SSH)
    17:  ("UDP",  C.YELLOW),   # Fast data (video, DNS, games)
    41:  ("IPv6", C.MAGENTA),  # Next-gen Internet Protocol
    47:  ("GRE",  C.BLUE),     # Tunneling protocol
    50:  ("ESP",  C.RED),      # VPN encryption
    58:  ("ICMPv6", C.CYAN),   # Ping for IPv6
}

# ──────────────────────────────────────────────
#  WELL-KNOWN PORTS  —  port number → service name
#  (Ports are like doors — each service has its own)
# ──────────────────────────────────────────────
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

# ──────────────────────────────────────────────────────────────────
#  PACKET COUNTER  —  keeps stats for the session summary
# ──────────────────────────────────────────────────────────────────
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0, "TOTAL": 0}
log_lines = []   # stores log entries to write to file at the end


# ══════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════

def banner():
    """Print the startup banner."""
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗    ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║       ███████╗██║     ██║   ██║██████╔╝█████╗  
  ██║╚██╗██║██╔══╝     ██║       ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
  ██║ ╚████║███████╗   ██║       ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
{C.RESET}
{C.YELLOW}        🔬  Basic Network Sniffer  |  CodeAlpha Internship — Task 1  🔬{C.RESET}
{C.DIM}        Watching your network so you can understand what's flowing through it.{C.RESET}
    """)


def separator(char="─", width=70, color=C.DIM):
    """Print a styled horizontal line."""
    print(f"{color}{char * width}{C.RESET}")


def timestamp():
    """Return current time as a neat string."""
    return datetime.datetime.now().strftime("%H:%M:%S")


def format_ip(raw_bytes):
    """
    Convert 4 raw bytes into a human-readable IP address.
    e.g.  b'\\xc0\\xa8\\x01\\x01'  →  '192.168.1.1'
    """
    return ".".join(map(str, raw_bytes))


def get_service(port):
    """Return service name for a known port, or just the number."""
    return PORT_SERVICES.get(port, str(port))


def safe_payload(data, max_bytes=64):
    """
    Show payload bytes as readable text.
    Non-printable characters are replaced with a dot (.)
    This mimics what Wireshark does in its 'ASCII' column.
    """
    printable = ""
    for byte in data[:max_bytes]:
        ch = chr(byte)
        printable += ch if ch.isprintable() and ch != "\n" else "."
    if len(data) > max_bytes:
        printable += f"  … (+{len(data) - max_bytes} more bytes)"
    return printable


# ══════════════════════════════════════════════════════════════════
#  PACKET PARSERS
#  A packet is just a stream of bytes. We 'unpack' specific byte
#  positions to extract fields like source IP, destination IP, etc.
# ══════════════════════════════════════════════════════════════════

def parse_ethernet(raw_data):
    """
    Ethernet frame structure (first 14 bytes):
    ┌─────────────────┬─────────────────┬───────────┐
    │  Dest MAC (6B)  │  Src MAC (6B)   │ Type (2B) │
    └─────────────────┴─────────────────┴───────────┘
    Returns: dest_mac, src_mac, eth_type, remaining_data
    """
    dest_mac, src_mac, eth_type = struct.unpack("! 6s 6s H", raw_data[:14])
    dest_mac = ":".join(f"{b:02x}" for b in dest_mac)
    src_mac  = ":".join(f"{b:02x}" for b in src_mac)
    return dest_mac, src_mac, eth_type, raw_data[14:]


def parse_ipv4(data):
    """
    IPv4 header (minimum 20 bytes):
    Byte 0   : Version + Header Length
    Byte 9   : Protocol (TCP=6, UDP=17, ICMP=1)
    Bytes 12-15 : Source IP
    Bytes 16-19 : Destination IP

    '!' = network byte order (big-endian)
    'B' = 1 unsigned byte
    'H' = 2 unsigned bytes (short)
    '4s' = 4 raw bytes (we convert to IP string)
    """
    version_ihl = data[0]
    ihl = (version_ihl & 0xF) * 4   # header length in bytes
    ttl, proto, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    src_ip = format_ip(src)
    dst_ip = format_ip(dst)
    return ihl, ttl, proto, src_ip, dst_ip, data[ihl:]


def parse_tcp(data):
    """
    TCP header (first 20 bytes at minimum):
    Bytes 0-1: Source Port
    Bytes 2-3: Destination Port
    Bytes 4-7: Sequence Number
    Byte 12  : Data Offset (header length)
    Byte 13  : Flags (SYN, ACK, FIN, RST, PSH, URG)
    """
    src_port, dst_port, seq, ack, offset_flags = struct.unpack(
        "! H H L L H", data[:14]
    )
    offset = (offset_flags >> 12) * 4   # actual header size
    flags  = offset_flags & 0x1FF       # last 9 bits = flags

    flag_str = ""
    if flags & 0x002: flag_str += "SYN "
    if flags & 0x010: flag_str += "ACK "
    if flags & 0x001: flag_str += "FIN "
    if flags & 0x004: flag_str += "RST "
    if flags & 0x008: flag_str += "PSH "
    if flags & 0x020: flag_str += "URG "

    return src_port, dst_port, seq, ack, flag_str.strip(), data[offset:]


def parse_udp(data):
    """
    UDP header (exactly 8 bytes):
    Bytes 0-1: Source Port
    Bytes 2-3: Destination Port
    Bytes 4-5: Length
    Bytes 6-7: Checksum
    """
    src_port, dst_port, length = struct.unpack("! H H H 2x", data[:8])
    return src_port, dst_port, length, data[8:]


def parse_icmp(data):
    """
    ICMP header (8 bytes):
    Byte 0 : Type  (8=Echo Request / Ping, 0=Echo Reply / Pong)
    Byte 1 : Code
    Bytes 2-3: Checksum
    """
    icmp_type, code, checksum = struct.unpack("! B B H 4x", data[:8])
    type_map = {
        0: "Echo Reply (Pong 🏓)",
        3: "Destination Unreachable ❌",
        8: "Echo Request (Ping 🏓)",
        11: "Time Exceeded ⏱️",
    }
    type_name = type_map.get(icmp_type, f"Type {icmp_type}")
    return icmp_type, code, checksum, type_name, data[8:]


# ══════════════════════════════════════════════════════════════════
#  DISPLAY FUNCTIONS  —  pretty-print each packet type
# ══════════════════════════════════════════════════════════════════

def print_packet_header(count, src_ip, dst_ip, proto_name, proto_color):
    """Top bar shown for every packet."""
    separator("═", 70, proto_color)
    print(
        f"{proto_color}{C.BOLD}  [{count:04d}] {timestamp()}  "
        f"│  {proto_name:<6}  │  "
        f"{src_ip}  →  {dst_ip}{C.RESET}"
    )


def print_tcp_packet(src_ip, dst_ip, count, payload, src_port, dst_port, seq, flags):
    print_packet_header(count, src_ip, dst_ip, "TCP", C.GREEN)
    src_svc = get_service(src_port)
    dst_svc = get_service(dst_port)
    print(f"{C.GREEN}  Port  : {src_svc} → {dst_svc}    "
          f"Flags: {C.BOLD}{flags if flags else '—'}{C.RESET}")
    print(f"{C.DIM}  Seq   : {seq}{C.RESET}")
    if payload:
        readable = safe_payload(payload)
        print(f"{C.DIM}  Data  : {readable}{C.RESET}")


def print_udp_packet(src_ip, dst_ip, count, payload, src_port, dst_port, length):
    print_packet_header(count, src_ip, dst_ip, "UDP", C.YELLOW)
    src_svc = get_service(src_port)
    dst_svc = get_service(dst_port)
    print(f"{C.YELLOW}  Port  : {src_svc} → {dst_svc}    Length: {length}{C.RESET}")
    if payload:
        readable = safe_payload(payload)
        print(f"{C.DIM}  Data  : {readable}{C.RESET}")


def print_icmp_packet(src_ip, dst_ip, count, type_name):
    print_packet_header(count, src_ip, dst_ip, "ICMP", C.CYAN)
    print(f"{C.CYAN}  Type  : {type_name}{C.RESET}")


def print_other_packet(src_ip, dst_ip, count, proto_num, proto_name, proto_color):
    print_packet_header(count, src_ip, dst_ip, proto_name, proto_color)
    print(f"{proto_color}  Protocol Number: {proto_num}{C.RESET}")


# ══════════════════════════════════════════════════════════════════
#  LOG WRITER  —  saves captured data to a text file
# ══════════════════════════════════════════════════════════════════

def log_packet(line):
    """Add a line to our session log."""
    log_lines.append(line)


def save_log():
    """Write all captured packets to a log file."""
    filename = f"netscope_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write("NetScope — Packet Capture Log\n")
        f.write(f"Session: {datetime.datetime.now()}\n")
        f.write("=" * 60 + "\n\n")
        for line in log_lines:
            f.write(line + "\n")
        f.write("\n\n--- SESSION STATS ---\n")
        for k, v in stats.items():
            f.write(f"{k}: {v}\n")
    print(f"\n{C.GREEN}  ✅ Log saved → {filename}{C.RESET}")


# ══════════════════════════════════════════════════════════════════
#  SESSION SUMMARY  —  shown when the user stops the sniffer
# ══════════════════════════════════════════════════════════════════

def print_summary():
    separator("═", 70, C.MAGENTA)
    print(f"\n{C.MAGENTA}{C.BOLD}  📊  SESSION SUMMARY{C.RESET}")
    separator("─", 70, C.MAGENTA)
    print(f"  {'TOTAL PACKETS':<20}: {C.BOLD}{stats['TOTAL']}{C.RESET}")
    print(f"  {'TCP':<20}: {C.GREEN}{stats['TCP']}{C.RESET}")
    print(f"  {'UDP':<20}: {C.YELLOW}{stats['UDP']}{C.RESET}")
    print(f"  {'ICMP':<20}: {C.CYAN}{stats['ICMP']}{C.RESET}")
    print(f"  {'OTHER':<20}: {C.DIM}{stats['OTHER']}{C.RESET}")
    separator("═", 70, C.MAGENTA)


# ══════════════════════════════════════════════════════════════════
#  MAIN SNIFFER LOOP
# ══════════════════════════════════════════════════════════════════

def run_sniffer(packet_limit=0, filter_proto=None):
    """
    Core function — opens a raw socket and listens for packets.

    RAW SOCKET = a special socket that captures all packets at
    the network layer, before the OS filters them by port/app.

    AF_PACKET  : Linux-specific; captures at Ethernet layer.
    SOCK_RAW   : Raw mode — we get the full unfiltered packet.
    ETH_P_ALL  : Capture every protocol (not just TCP/IP).
    """
    try:
        # Open the raw socket (needs root / admin privileges)
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(0x0003))
    except PermissionError:
        print(f"\n{C.RED}  ❌ Permission denied!{C.RESET}")
        print(f"  Run with: {C.BOLD}sudo python3 sniffer.py{C.RESET}\n")
        sys.exit(1)
    except OSError:
        print(f"\n{C.RED}  ❌ Raw sockets not supported on this OS.{C.RESET}")
        print(f"  {C.YELLOW}Try running on Linux (or WSL on Windows).{C.RESET}\n")
        sys.exit(1)

    banner()
    print(f"  {C.GREEN}✅ Sniffer active!  Press {C.BOLD}Ctrl+C{C.RESET}{C.GREEN} to stop.{C.RESET}")
    if packet_limit:
        print(f"  {C.DIM}Capturing up to {packet_limit} packets...{C.RESET}")
    if filter_proto:
        print(f"  {C.DIM}Filter: showing only {filter_proto} packets{C.RESET}")
    separator()

    count = 0

    try:
        while True:
            # recvfrom() blocks here until a packet arrives
            raw_data, _ = conn.recvfrom(65536)   # 65536 = max packet size

            # ── Step 1: Parse Ethernet Header ──────────────────────
            dest_mac, src_mac, eth_type, ip_data = parse_ethernet(raw_data)

            # We only care about IPv4 packets (eth_type 0x0800 = 2048)
            if eth_type != 8:    # 8 = IPv4 in decimal
                continue

            # ── Step 2: Parse IPv4 Header ──────────────────────────
            ihl, ttl, proto_num, src_ip, dst_ip, transport_data = parse_ipv4(ip_data)

            # Protocol info
            proto_info  = PROTOCOL_MAP.get(proto_num, (f"PROTO-{proto_num}", C.WHITE))
            proto_name  = proto_info[0]
            proto_color = proto_info[1]

            # Apply protocol filter if user specified one
            if filter_proto and proto_name != filter_proto.upper():
                continue

            count += 1
            stats["TOTAL"] += 1

            log_entry = f"[{count}] {timestamp()} | {proto_name} | {src_ip} → {dst_ip}"

            # ── Step 3: Parse Transport Layer (TCP / UDP / ICMP) ───
            if proto_num == 6:   # TCP
                stats["TCP"] += 1
                src_port, dst_port, seq, ack, flags, payload = parse_tcp(transport_data)
                print_tcp_packet(src_ip, dst_ip, count, payload,
                                 src_port, dst_port, seq, flags)
                log_entry += f" | Port {src_port}→{dst_port} | Flags: {flags}"

            elif proto_num == 17:   # UDP
                stats["UDP"] += 1
                src_port, dst_port, length, payload = parse_udp(transport_data)
                print_udp_packet(src_ip, dst_ip, count, payload,
                                 src_port, dst_port, length)
                log_entry += f" | Port {src_port}→{dst_port}"

            elif proto_num == 1:   # ICMP
                stats["ICMP"] += 1
                icmp_type, code, checksum, type_name, payload = parse_icmp(transport_data)
                print_icmp_packet(src_ip, dst_ip, count, type_name)
                log_entry += f" | {type_name}"

            else:
                stats["OTHER"] += 1
                print_other_packet(src_ip, dst_ip, count, proto_num,
                                   proto_name, proto_color)

            log_packet(log_entry)

            # Stop after N packets if limit was set
            if packet_limit and count >= packet_limit:
                print(f"\n{C.YELLOW}  ✅ Reached packet limit of {packet_limit}.{C.RESET}")
                break

    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}  👋 Sniffer stopped by user.{C.RESET}")

    finally:
        conn.close()
        print_summary()
        save_log()


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    You can customise these two settings:

    packet_limit : How many packets to capture before auto-stopping.
                   Set to 0 for unlimited (stop manually with Ctrl+C).

    filter_proto : Show only packets of a specific protocol.
                   Options: "TCP", "UDP", "ICMP", or None for all.
    """
    run_sniffer(
        packet_limit=0,      # 0 = capture until Ctrl+C
        filter_proto=None,   # None = capture all protocols
    )

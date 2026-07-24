"""
PCAP Feature Extractor using dpkt
Extracts 47 network flow features from a pcap file.
Supports all attack types — outputs a CSV with one row per flow.

Supported attacks:
    TCP Floods: SYN, ACK, FIN, RST, PSH+ACK, SYN+ACK, FIN+RST
    Fragmentation: UDP Frag, ICMP Frag (PoD), ACK Frag
    Other: UDP Flood, ICMP Flood, Raw IP, Land Attack, Spoofed IP

Usage:
    python pcap_feature_extractor.py <input.pcap> [output.csv]

Requirements:
    pip install dpkt numpy
"""

import sys
import csv
import math
import socket
import struct
from collections import defaultdict

import dpkt
import numpy as np



def safe_div(a, b):
    return a / b if b else 0.0


def safe_float(val):
    try:
        if math.isnan(val) or math.isinf(val):
            return 0.0
        return float(val)
    except Exception:
        return 0.0


def ip_to_str(addr):
    try:
        return socket.inet_ntoa(addr)
    except Exception:
        return str(addr)


def detect_app_protocol(sport, dport, proto_name):
    ports = {sport, dport}
    if 80  in ports: return "HTTP"
    if 443 in ports: return "HTTPS"
    if 53  in ports: return "DNS"
    if 23  in ports: return "Telnet"
    if 25  in ports or 587 in ports or 465 in ports: return "SMTP"
    if 22  in ports: return "SSH"
    if 194 in ports or 6667 in ports or 6668 in ports or 6669 in ports: return "IRC"
    if 67  in ports or 68  in ports: return "DHCP"
    return "Unknown"



# TCP flag analysis

def parse_tcp_flags(flags_val):
    return {
        "fin": int(bool(flags_val & dpkt.tcp.TH_FIN)),
        "syn": int(bool(flags_val & dpkt.tcp.TH_SYN)),
        "rst": int(bool(flags_val & dpkt.tcp.TH_RST)),
        "psh": int(bool(flags_val & dpkt.tcp.TH_PUSH)),
        "ack": int(bool(flags_val & dpkt.tcp.TH_ACK)),
        "urg": int(bool(flags_val & dpkt.tcp.TH_URG)),
        "ece": int(bool(flags_val & dpkt.tcp.TH_ECE)),
        "cwr": int(bool(flags_val & dpkt.tcp.TH_CWR)),
    }


def classify_tcp_flood(flags):
    """
    Classify TCP flood type from flag combination.
    Used for transport_name to give more granular info.
    All still map to TCP=1 in features.
    """
    syn = flags.get("syn", 0)
    ack = flags.get("ack", 0)
    fin = flags.get("fin", 0)
    rst = flags.get("rst", 0)
    psh = flags.get("psh", 0)

    if syn and ack:   return "TCP_SYNACK"    # SYN-ACK flood
    if fin and rst:   return "TCP_FINRST"    # FIN+RST flood
    if psh and ack:   return "TCP_PSHACK"    # PSH+ACK flood
    if syn:           return "TCP_SYN"       # SYN flood
    if ack:           return "TCP_ACK"       # ACK flood
    if fin:           return "TCP_FIN"       # FIN flood
    if rst:           return "TCP_RST"       # RST flood
    return "TCP"



def get_ip_flags_frag(ip):
    """
    Read flags + fragment offset from raw IP header bytes 6-7.
    [3-bit flags | 13-bit frag offset]
    Bypasses deprecated ip.off and all dpkt version issues.
    """
    try:
        raw        = bytes(ip)
        flags_frag = (raw[6] << 8) | raw[7]
        more_frags = (flags_frag >> 13) & 0x1
        frag_off   = flags_frag & 0x1FFF
        return more_frags, frag_off
    except Exception:
        return 0, 0


def is_fragment(ip):
    more_frags, frag_off = get_ip_flags_frag(ip)
    return more_frags == 1 or frag_off > 0


def classify_frag_transport(ip_proto):
    """
    Map IP protocol number to fragment transport name.
    Covers UDP frag, ICMP frag (PoD), TCP frag, ACK frag, Raw IP frag.
    """
    if ip_proto == dpkt.ip.IP_PROTO_ICMP: return "ICMP_FRAG"   # Ping of Death
    if ip_proto == dpkt.ip.IP_PROTO_UDP:  return "UDP_FRAG"    # UDP fragmentation
    if ip_proto == dpkt.ip.IP_PROTO_TCP:  return "TCP_FRAG"    # ACK/TCP fragmentation
    return "UNKNOWN_FRAG"                                        # Raw IP / other

# Flow keys

def flow_key(src_ip, dst_ip, sport, dport, proto):
    """Standard bidirectional 5-tuple key for TCP/UDP flows."""
    ep1 = (src_ip, sport)
    ep2 = (dst_ip, dport)
    if ep1 > ep2:
        ep1, ep2 = ep2, ep1
    return (proto, ep1[0], ep1[1], ep2[0], ep2[1])


def frag_flow_key(src_ip, dst_ip, ip_id, proto):
    """
    Key for portless fragmented flows (ICMP PoD, Raw IP, ACK frag with no ports).
    Uses ip.id as discriminator. src NOT sorted — unidirectional spoofed traffic.
    """
    return (proto, src_ip, ip_id, dst_ip, 0)


def land_attack_key(ip_addr, sport, proto):
    """
    Key for Land Attack where src_ip == dst_ip and sport == dport.
    Uses sport as discriminator since both endpoints are identical.
    """
    return (proto, ip_addr, sport, ip_addr, sport)



# Fragment port cache

frag_port_cache = {}


def get_frag_ports(ip, buf_data):
    """
    Extract sport/dport from first fragment (frag_off=0) for UDP/TCP.
    ICMP and Raw IP fragments return (0,0) — they use frag_flow_key.
    """
    src       = ip_to_str(ip.src)
    dst       = ip_to_str(ip.dst)
    proto     = ip.p
    ip_id     = ip.id
    cache_key = (src, dst, ip_id, proto)

    _, frag_off = get_ip_flags_frag(ip)

    if frag_off == 0:
        try:
            if proto == dpkt.ip.IP_PROTO_UDP and len(buf_data) >= 8:
                sport, dport, _, _ = struct.unpack("!HHHH", buf_data[:8])
                frag_port_cache[cache_key] = (sport, dport)
                return sport, dport
            elif proto == dpkt.ip.IP_PROTO_TCP and len(buf_data) >= 4:
                sport, dport = struct.unpack("!HH", buf_data[:4])
                frag_port_cache[cache_key] = (sport, dport)
                return sport, dport
        except Exception:
            pass
        return 0, 0
    else:
        return frag_port_cache.get(cache_key, (0, 0))



# Land attack detection

def is_land_attack(src_ip, dst_ip, sport, dport):
    """
    Land attack: src_ip == dst_ip AND sport == dport.
    """
    return src_ip == dst_ip and sport == dport and sport != 0



# Spoofed IP detection


def is_spoofed_ip(src_ip):
    """
    Heuristic: flags IPs that are clearly spoofed.
    Covers reserved, loopback, multicast, and link-local ranges.
    """
    try:
        parts = list(map(int, src_ip.split(".")))
        if parts[0] == 127:          return True   # loopback
        if parts[0] == 0:            return True   # reserved
        if parts[0] >= 224:          return True   # multicast / reserved
        if parts[0] == 169 and parts[1] == 254: return True  # link-local
        return False
    except Exception:
        return False


# 
# Flow record

class Flow:
    __slots__ = [
        "start_ts", "end_ts", "timestamps",
        "header_lengths", "protocol_type",
        "fin", "syn", "rst", "psh", "ack", "ece", "cwr", "urg",
        "pkt_lengths",
        "src_lengths", "dst_lengths",
        "src_pkts", "dst_pkts",
        "initiator_src",
        "app_proto", "transport_proto", "link_proto",
        "ip_src", "ip_dst",
        "is_land", "is_spoofed",
    ]

    def __init__(self):
        self.start_ts        = None
        self.end_ts          = None
        self.timestamps      = []
        self.header_lengths  = []
        self.protocol_type   = 0
        self.fin = self.syn  = self.rst = self.psh = 0
        self.ack = self.ece  = self.cwr = self.urg = 0
        self.pkt_lengths     = []
        self.src_lengths     = []
        self.dst_lengths     = []
        self.src_pkts        = 0
        self.dst_pkts        = 0
        self.initiator_src   = None
        self.app_proto       = "Unknown"
        self.transport_proto = "Unknown"
        self.link_proto      = "Unknown"
        self.ip_src          = ""
        self.ip_dst          = ""
        self.is_land         = False
        self.is_spoofed      = False


# Feature CSV columns (47)

COLUMNS = [
    "ip_src", "ip_dst", "ts",
    "flow_duration", "Header_Length", "Protocol_Type", "Duration",
    "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_numbe", "ack_flag_number", "ece_flag_numbe", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Tot_sum", "Min", "Max", "AVG", "Std",
    "Tot_size", "IAT", "Number",
    "Magnitude", "Radius", "Covariance", "Variance", "Weight",
]



# Feature computation

def compute_features(flow: Flow) -> dict:
    dur    = (flow.end_ts - flow.start_ts) if flow.start_ts != flow.end_ts else 1e-9
    n_pkts = len(flow.pkt_lengths)

    iats    = [flow.timestamps[i] - flow.timestamps[i-1] for i in range(1, len(flow.timestamps))]
    avg_iat = safe_float(np.mean(iats)) if iats else 0.0

    lengths = np.array(flow.pkt_lengths, dtype=float) if flow.pkt_lengths else np.array([0.0])
    tot_sum = safe_float(lengths.sum())
    pkt_min = safe_float(lengths.min())
    pkt_max = safe_float(lengths.max())
    pkt_avg = safe_float(lengths.mean())
    pkt_std = safe_float(lengths.std())

    src_arr = np.array(flow.src_lengths, dtype=float) if flow.src_lengths else np.array([0.0])
    dst_arr = np.array(flow.dst_lengths, dtype=float) if flow.dst_lengths else np.array([0.0])

    src_avg = safe_float(src_arr.mean())
    dst_avg = safe_float(dst_arr.mean())
    src_var = safe_float(src_arr.var())
    dst_var = safe_float(dst_arr.var())

    magnitude = safe_float(math.sqrt(max(src_avg + dst_avg, 0)))
    radius    = safe_float(math.sqrt(max(src_var + dst_var, 0)))

    if len(lengths) >= 3:
        cov_matrix = np.cov(lengths[:-1], lengths[1:])
        covariance = safe_float(cov_matrix[0][1] if cov_matrix.ndim == 2 else 0.0)
    else:
        covariance = 0.0

    variance_val = safe_float(lengths.var()) if len(lengths) >= 2 else 0.0
    weight       = float(n_pkts)
    rate         = safe_float(safe_div(n_pkts, dur))
    srate        = safe_float(safe_div(flow.src_pkts, dur))
    drate        = safe_float(safe_div(flow.dst_pkts, dur))

    app = flow.app_proto
    tp  = flow.transport_proto
    lp  = flow.link_proto

    # TCP=1 for all TCP variants including fragments and flood types
    is_tcp = int(tp in (
        "TCP", "TCP_SYN", "TCP_ACK", "TCP_FIN", "TCP_RST",
        "TCP_SYNACK", "TCP_FINRST", "TCP_PSHACK", "TCP_FRAG"
    ))

    # UDP=1 for normal UDP and fragmented UDP
    is_udp = int(tp in ("UDP", "UDP_FRAG"))

    # ICMP=1 for normal ICMP and fragmented ICMP (PoD)
    is_icmp = int(tp in ("ICMP", "ICMP_FRAG"))

    return {
        "ip_src":           flow.ip_src,
        "ip_dst":           flow.ip_dst,
        "ts":               flow.start_ts,
        "flow_duration":    safe_float(dur),
        "Header_Length":    safe_float(np.mean(flow.header_lengths)) if flow.header_lengths else 0.0,
        "Protocol_Type":    flow.protocol_type,
        "Duration":         safe_float(dur),
        "Rate":             rate,
        "Srate":            srate,
        "Drate":            drate,
        "fin_flag_number":  flow.fin,
        "syn_flag_number":  flow.syn,
        "rst_flag_number":  flow.rst,
        "psh_flag_numbe":   flow.psh,
        "ack_flag_number":  flow.ack,
        "ece_flag_numbe":   flow.ece,
        "cwr_flag_number":  flow.cwr,
        "ack_count":        flow.ack,
        "syn_count":        flow.syn,
        "fin_count":        flow.fin,
        "urg_count":        flow.urg,
        "rst_count":        flow.rst,
        "HTTP":   int(app == "HTTP"),
        "HTTPS":  int(app == "HTTPS"),
        "DNS":    int(app == "DNS"),
        "Telnet": int(app == "Telnet"),
        "SMTP":   int(app == "SMTP"),
        "SSH":    int(app == "SSH"),
        "IRC":    int(app == "IRC"),
        "TCP":    is_tcp,
        "UDP":    is_udp,
        "DHCP":   int(app == "DHCP"),
        "ARP":    int(lp == "ARP"),
        "ICMP":   is_icmp,
        "IPv":    int(lp == "IPv"),
        "LLC":    int(lp == "LLC"),
        "Tot_sum":    tot_sum,
        "Min":        pkt_min,
        "Max":        pkt_max,
        "AVG":        pkt_avg,
        "Std":        pkt_std,
        "Tot_size":   tot_sum,
        "IAT":        avg_iat,
        "Number":     n_pkts,
        "Magnitude":  magnitude,
        "Radius":     radius,
        "Covariance": covariance,
        "Variance":   variance_val,
        "Weight":     weight,
    }



# PCAP parsing

def parse_pcap(pcap_path: str):
    flows      = defaultdict(Flow)
    total_pkts = 0

    with open(pcap_path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
            print("[*] File format : pcap")
        except Exception:
            f.seek(0)
            try:
                pcap = dpkt.pcapng.Reader(f)
                print("[*] File format : pcapng")
            except Exception as e:
                print(f"[ERROR] Cannot open file: {e}")
                sys.exit(1)

        link_type = pcap.datalink()
        print(f"[*] Link type   : {link_type}")

        for ts, buf in pcap:
            total_pkts += 1
            if total_pkts % 10000 == 0:
                print(f"[*] Packets read: {total_pkts} | Flows: {len(flows)}")

            try:
                ip        = None
                link_name = "Unknown"

                # ── Layer 2 parsing
                if link_type == dpkt.pcap.DLT_EN10MB:
                    eth       = dpkt.ethernet.Ethernet(buf)
                    link_name = "IPv"

                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data

                    elif isinstance(eth.data, dpkt.arp.ARP):
                        arp = eth.data
                        key = ("ARP", ip_to_str(arp.spa), 0, ip_to_str(arp.tpa), 0)
                        fl  = flows[key]
                        fl.link_proto      = "ARP"
                        fl.transport_proto = "ARP"
                        fl.ip_src          = ip_to_str(arp.spa)
                        fl.ip_dst          = ip_to_str(arp.tpa)
                        fl.pkt_lengths.append(len(buf))
                        fl.timestamps.append(ts)
                        if fl.start_ts is None:
                            fl.start_ts = ts
                        fl.end_ts = ts
                        continue
                    else:
                        continue

                elif link_type == dpkt.pcap.DLT_RAW:
                    ip        = dpkt.ip.IP(buf)
                    link_name = "IPv"
                else:
                    try:
                        ip        = dpkt.ip.IP(buf)
                        link_name = "IPv"
                    except Exception:
                        continue

                if ip is None:
                    continue

                transport      = ip.data
                sport = dport  = 0
                tcp_flags      = {}
                transport_name = "Unknown"
                fragmented     = is_fragment(ip)

                src_ip_str = ip_to_str(ip.src)
                dst_ip_str = ip_to_str(ip.dst)

                # ── Transport classification
                if fragmented:
                    sport, dport   = get_frag_ports(ip, bytes(transport))
                    transport_name = classify_frag_transport(ip.p)

                elif isinstance(transport, dpkt.tcp.TCP):
                    sport, dport = transport.sport, transport.dport
                    tcp_flags    = parse_tcp_flags(transport.flags)
                    transport_name = classify_tcp_flood(tcp_flags)

                elif isinstance(transport, dpkt.udp.UDP):
                    transport_name = "UDP"
                    sport, dport   = transport.sport, transport.dport

                elif isinstance(transport, dpkt.icmp.ICMP):
                    transport_name = "ICMP"

                # ── Flow key selection
                if is_land_attack(src_ip_str, dst_ip_str, sport, dport):
                    # Land attack: src=dst, sport=dport
                    key = land_attack_key(src_ip_str, sport, ip.p)

                elif fragmented and transport_name in ("ICMP_FRAG", "UNKNOWN_FRAG") or \
                     (fragmented and transport_name in ("UDP_FRAG", "TCP_FRAG") and sport == 0 and dport == 0):
                    # Portless fragments — use ip.id to separate flows
                    key = frag_flow_key(src_ip_str, dst_ip_str, ip.id, ip.p)

                else:
                    # Standard 5-tuple key for all other flows
                    key = flow_key(src_ip_str, dst_ip_str, sport, dport, ip.p)

                fl = flows[key]

                if fl.start_ts is None:
                    fl.start_ts        = ts
                    fl.initiator_src   = src_ip_str
                    fl.ip_src          = src_ip_str
                    fl.ip_dst          = dst_ip_str
                    fl.transport_proto = transport_name
                    fl.link_proto      = link_name
                    fl.protocol_type   = ip.p
                    fl.is_land         = is_land_attack(src_ip_str, dst_ip_str, sport, dport)
                    fl.is_spoofed      = is_spoofed_ip(src_ip_str)
                    if transport_name in ("TCP", "UDP", "UDP_FRAG") or transport_name.startswith("TCP_"):
                        fl.app_proto = detect_app_protocol(sport, dport, transport_name)

                fl.end_ts = ts
                fl.timestamps.append(ts)

                pkt_len = len(buf)
                fl.pkt_lengths.append(pkt_len)
                fl.header_lengths.append(ip.hl * 4)

                if src_ip_str == fl.initiator_src:
                    fl.src_lengths.append(pkt_len)
                    fl.src_pkts += 1
                else:
                    fl.dst_lengths.append(pkt_len)
                    fl.dst_pkts += 1

                if tcp_flags:
                    fl.fin += tcp_flags.get("fin", 0)
                    fl.syn += tcp_flags.get("syn", 0)
                    fl.rst += tcp_flags.get("rst", 0)
                    fl.psh += tcp_flags.get("psh", 0)
                    fl.ack += tcp_flags.get("ack", 0)
                    fl.urg += tcp_flags.get("urg", 0)
                    fl.ece += tcp_flags.get("ece", 0)
                    fl.cwr += tcp_flags.get("cwr", 0)

            except Exception:
                continue

    return flows


# Main


def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_feature_extractor.py <input.pcap> [output.csv]")
        sys.exit(1)

    pcap_path  = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else "features.csv"

    print(f"[*] Parsing: {pcap_path}")
    flows = parse_pcap(pcap_path)
    print(f"[*] Flows found: {len(flows)}")

    written = 0
    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=COLUMNS)
        writer.writeheader()
        for key, flow in flows.items():
            if flow.start_ts is None:
                continue
            row = compute_features(flow)
            writer.writerow({col: row[col] for col in COLUMNS})
            written += 1

    print(f"[+] Done. {written} flow records written to: {output_csv}")


if __name__ == "__main__":
    main()
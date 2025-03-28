import re
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, Raw
from urllib.parse import unquote, parse_qs
from scapy.layers.http import HTTPRequest, HTTPResponse

# Config
PCAP_FILE = "challenge.pcapng"
PRINTABLE_ONLY = True  # Set to False to allow full ASCII range

# Regex patterns
mid_re = re.compile(r"ORD\(MID\(\(SELECT.*?\),(\d+),1\)\)", re.IGNORECASE)
select_re = re.compile(r"SELECT\s+(.*?)\s+FROM", re.IGNORECASE)
limit_re = re.compile(r"LIMIT\s+(\d+),1", re.IGNORECASE)
field_re = re.compile(r"CAST\(`?([a-zA-Z_]+)`?\s+AS\s+NCHAR", re.IGNORECASE)


def load_pcap(file_path):
    return rdpcap(file_path)


def pair_requests(packets):
    pairs = {}
    for pkt in packets:
        if pkt.haslayer(HTTPRequest):
            try:
                path = pkt[HTTPRequest].Path.decode()
                query = parse_qs(unquote(path.split("?", 1)[1])).get("query", [None])[0]
                if not query or ">" not in query:
                    continue
                condition, val = query.rsplit(">", 1)
                pos = int(mid_re.search(condition).group(1))
                val = int(val)
            except:
                continue
            stream = (
                pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].ack
            )
            pairs[stream] = {"condition": condition, "position": pos, "value": val}
        elif pkt.haslayer(HTTPResponse) and pkt.haslayer(Raw):
            stream = (
                pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport, pkt[TCP].seq
            )
            if stream in pairs:
                body = pkt[Raw].load
                pairs[stream]["success"] = b"No results found" not in body
    return pairs


def extract_ascii(pairs):
    results = defaultdict(dict)
    for stream in pairs.values():
        if "success" not in stream:
            continue
        cond, val, pos = stream["condition"], stream["value"], stream["position"]

        sel = select_re.search(cond)
        expr = sel.group(1).strip() if sel else cond.split("ORD")[0].strip()
        if any(term in expr.lower() for term in ["char_length", "count"]):
            continue

        lim = limit_re.search(cond)
        key = f"{expr} [LIMIT {lim.group(1)},1]" if lim else expr

        if pos not in results[key]:
            results[key][pos] = [0, 255]

        if stream["success"]:
            results[key][pos][0] = max(results[key][pos][0], val)
        else:
            results[key][pos][1] = min(results[key][pos][1], val)
    return results


def build_table(results):
    table = defaultdict(dict)
    for target, chars in results.items():
        sorted_chars = sorted(chars.items())
        out = ""
        for _, (min_val, max_val) in sorted_chars:
            char = chr(max_val)
            if PRINTABLE_ONLY and not (32 <= max_val <= 126):
                continue
            out += char
        out = out.strip()

        lim = limit_re.search(target)
        field = field_re.search(target)
        if not lim or not field:
            continue
        row = lim.group(1)
        column = field.group(1)
        table[row][column] = out
    return table


def print_table(table):
    print("Reconstructed Table:\n")
    for row in sorted(table.keys(), key=int):
        print(f"Row {row}:")
        for col in ("id", "name", "description"):
            print(f"  {col:12}: {table[row].get(col, '[missing]')}")
        print()


# --- Run the full pipeline ---
if __name__ == "__main__":
    packets = load_pcap(PCAP_FILE)
    paired = pair_requests(packets)
    ascii_results = extract_ascii(paired)
    db_table = build_table(ascii_results)
    print_table(db_table)


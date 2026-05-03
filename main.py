from scapy.all import sniff
import pandas as pd

def extrair_features(p):
    dados = {}

    dados["timestamp"] = p.time
    dados["tamanho"] = len(p)

    if p.haslayer("Ether"):
        dados["src_mac"] = p["Ether"].src
        dados["dst_mac"] = p["Ether"].dst

    if p.haslayer("IP"):
        dados["src_ip"] = p["IP"].src
        dados["dst_ip"] = p["IP"].dst
        dados["ttl"] = p["IP"].ttl
        dados["ip_len"] = p["IP"].len
        dados["proto"] = p["IP"].proto

    if p.haslayer("TCP"):
        dados["src_port"] = p["TCP"].sport
        dados["dst_port"] = p["TCP"].dport

    if p.haslayer("UDP"):
        dados["src_port"] = p["UDP"].sport
        dados["dst_port"] = p["UDP"].dport
        dados["udp_len"] = p["UDP"].len

    if p.haslayer("ICMP"):
        dados["icmp_type"] = p["ICMP"].type
        dados["icmp_code"] = p["ICMP"].code

    return dados

pacotes = sniff(count=3)

linhas = [extrair_features(p) for p in pacotes]

df = pd.DataFrame(linhas)

print(df.head())
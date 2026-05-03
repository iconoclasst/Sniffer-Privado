from scapy.all import sniff
import pandas as pd
from funcoes_auxiliares import *

pacotes = sniff()

linhas = [extrair_features(p) for p in pacotes]

df = pd.DataFrame(linhas)

pii = ['timestamp', 'src_mac', 'dst_mac', 'src_port', 'dst_port', 'src_ip', 'dst_ip', ]
qid = ['tamanho', 'ttl', 'ip_len', 'proto', 'udp_len']
remover = ['timestamp', 'src_ip', 'dst_ip', 'udp_len']

print("PII encontrados:")
print(pii)

print("Quase-identificadores encontrados:")
print(qid)

for coluna in remover:
    if coluna in df.columns:
        df.drop(columns=coluna, inplace=True)

generalizacao_tamanho(df)

if "src_port" in df.columns:
    generalizacao_portas(df, "src_port")
if "dst_port" in df.columns:
    generalizacao_portas(df, "dst_port")

if "src_mac" in df.columns:
    ofuscar_mac(df, "src_mac")
if "dst_mac" in df.columns:
    ofuscar_mac(df, "dst_mac")

print()
print()
print("Pacotes modificados")
print(df)
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

def generalizacao_tamanho(df):
    faixas = ['50-99', '100-149', '150-199', '200-499', '500-699', '700-999', '1000-1499', '1500-']

    def selecao(valor):
        if valor < 100:
            return faixas[0]
        elif valor < 150:
            return faixas[1]
        elif valor < 200:
            return faixas[2]
        elif valor < 500:
            return faixas[3]
        elif valor < 700:
            return faixas[4]
        elif valor < 1000:
            return faixas[5]
        elif valor < 1500:
            return faixas[6]
        else:
            return faixas[7]

    df['tamanho'] = df['tamanho'].apply(selecao)

def generalizacao_portas(df, coluna):
    faixas = ['0-299', '300-599','600-999','1000-1399', '1400-1999', '2000-7999', '8000-14999', '15000-19999', '20000-49999', '50000-65536']

    def selecao(valor):
        if pd.isna(valor):
            return valor
        if valor < 300:
            return faixas[0]
        elif valor < 600:
            return faixas[1]
        elif valor < 1000:
            return faixas[2]
        elif valor < 1400:
            return faixas[3]
        elif valor < 2000:
            return faixas[4]
        elif valor < 8000:
            return faixas[5]
        elif valor < 15000:
            return faixas[6]
        elif valor < 20000:
            return faixas[7]
        elif valor < 50000:
            return faixas[8]
        else:
            return faixas[9]

    df[coluna] = df[coluna].apply(selecao)

def ofuscar_mac(df, coluna):

    def mascara_mac(mac):
        if pd.isna(mac):
            return mac
        
        partes = mac.split(':')
        
        return ':'.join(partes[:2] + ['**'] * 4)
    
    df[coluna] = df[coluna].apply(mascara_mac)
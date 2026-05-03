# Sniffer Privado

Sniffer de rede em Python utilizando Scapy com foco em anonimização de dados sensíveis antes da análise.

O projeto captura pacotes da rede, extrai features principais e aplica técnicas simples de privacidade, como:
- remoção de identificadores diretos
- generalização de portas
- generalização de tamanho de pacotes
- mascaramento de endereços MAC

---

<img src="image.png" width=40%>

## Exemplo

Entrada capturada:

```text
src_mac = 5c:e3:0a:12:34:56
dst_mac = 28:0c:aa:bb:cc:dd
src_port = 443
dst_port = 53821
tamanho = 52
```

Saída anonimizada:

```text
src_mac = 5c:e3:**:**:**:**
dst_mac = 28:0c:**:**:**:**
src_port = 300-599
dst_port = 50000-65536
tamanho = 50-99
```

---

## Features extraídas

- timestamp
- tamanho do pacote
- MAC origem/destino
- IP origem/destino
- TTL
- protocolo IP
- portas TCP/UDP
- tamanho UDP
- tipo/código ICMP

---

## Técnicas de privacidade aplicadas

### Remoção de PII

Campos removidos:
- timestamp
- src_ip
- dst_ip
- udp_len

### Generalização

Faixas aplicadas em:
- tamanho dos pacotes
- portas TCP/UDP

### Ofuscação

Endereços MAC são parcialmente mascarados:

```text
5c:e3:0a:12:34:56
↓
5c:e3:**:**:**:**
```

---

## Exemplo de saída

```text
PII encontrados:
['timestamp', 'src_mac', 'dst_mac', 'src_port', 'dst_port', 'src_ip', 'dst_ip']

Quase-identificadores encontrados:
['tamanho', 'ttl', 'ip_len', 'proto', 'udp_len']

Pacotes modificados

  tamanho            src_mac            dst_mac  ttl  ip_len  proto src_port     dst_port
0   50-99  5c:e3:**:**:**:**  28:0c:**:**:**:**   99      52      6  300-599  50000-65536
```

# SCARFACE - Relatório de análise de logs

Gerado por SCARFACE v1.0.0 em 2026-09-19T01:48:18

## Metadados

| Campo | Valor |
|---|---|
| Arquivo | `demo_access.log` |
| Formato | apache (detectado) |
| Autor | DevPedroHenrique |
| Linhas totais | 26 |
| Linhas interpretadas | 26 |
| Linhas ignoradas | 0 |

## Resumo

- Brute force: **0** IP(s)
- Comprometimento: **0** IP(s)
- Escaneamento: **1** IP(s)
- Ataques em URL: **4** ocorrência(s)

## ALERTA - Escaneamento (rajada de 404)

- IP: `203.0.113.7` - 14 respostas 404 (14 caminhos distintos)
  - `/admin` (1x)
  - `/wp-login.php` (1x)
  - `/backup` (1x)

## ALERTA - Ataques nas URLs

| Tipo | IP | Ocorrências | Exemplo |
|---|---|---|---|
| XSS | `198.51.100.13` | 2 | `/busca.php?q=<script>alert(1)</script>` |
| Path Traversal | `198.51.100.13` | 2 | `/download.php?arquivo=../../etc/passwd` |

## IPs mais ativos

| Posição | IP | Eventos |
|---|---|---|
| 1 | `203.0.113.7` | 14 |
| 2 | `198.51.100.13` | 7 |
| 3 | `192.168.10.50` | 5 |

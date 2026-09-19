# SCARFACE - Relatório de análise de logs

Gerado por SCARFACE v1.0.0 em 2026-09-19T01:28:46

## Metadados

| Campo | Valor |
|---|---|
| Arquivo | `demo_auth.log` |
| Formato | auth (detectado) |
| Autor | DevPedroHenrique |
| Linhas totais | 47 |
| Linhas interpretadas | 47 |
| Linhas ignoradas | 0 |

## Resumo

- Brute force: **2** IP(s)
- Comprometimento: **1** IP(s)
- Escaneamento: **0** IP(s)
- Ataques em URL: **0** ocorrência(s)

## ALERTA - Brute force

- IP: `203.0.113.7`
- Falhas totais: 38
- Falhas na janela (300s): 38
- Alvo mais visado: `root` (19x)
- Período: 2026-09-17T09:12:00+00:00 ate 2026-09-17T09:12:59+00:00

- IP: `198.51.100.22`
- Falhas totais: 6
- Falhas na janela (300s): 6
- Alvo mais visado: `alice` (6x)
- Período: 2026-09-17T10:00:21+00:00 ate 2026-09-17T10:05:21+00:00

## ALERTA - Comprometimento em andamento

- IP: `198.51.100.22`
- Falhas anteriores: 6
- Login bem-sucedido: `alice` em 2026-09-17T10:07:45+00:00

## IPs mais ativos

| Posição | IP | Eventos |
|---|---|---|
| 1 | `203.0.113.7` | 38 |
| 2 | `198.51.100.22` | 7 |
| 3 | `192.168.10.50` | 2 |

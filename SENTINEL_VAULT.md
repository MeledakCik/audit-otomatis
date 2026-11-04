# Sentinel: Passive Audit + Redis Vault + Admin

## Setup
1. `npm i` (sudah menambah `bcryptjs`, `jose`)
2. Isi env di `.env.example` bagian "Sentinel Vault + Admin" (+ `UPSTASH_REDIS_REST_URL/TOKEN`)
3. `npm run build && npm start` / deploy Vercel

## Rute
| Rute | Fungsi |
|---|---|
| `/sentinel` | UI publik: audit, "Saya Pemilik Domain", lihat evidence 1x |
| `POST /api/sentinel/audit` | `{domain}` → hasil publik (tanpa secret) |
| `GET /api/sentinel/public/:domain` | hasil publik tersimpan (7 hari) |
| `POST/GET /api/sentinel/claim` | start / submit bukti / status |
| `GET /api/sentinel/view/:token` | one-time view (GETDEL) |
| `/admin/login` → `POST /api/admin/login` | login |
| `/admin/vault`, `/admin/requests` | panel admin |

## Redis keys
`sentinel:public:{domain}` 7d · `sentinel:vault:admin:{domain}:{id}` 24h (AES-256-GCM, AAD=nama key)
`sentinel:auth:{domain}:{userId}` 48h · `sentinel:temp:view:{token}` 10m · `session:admin:{jti}` 12h
`block:{ip}` 15m · `fail:{ip}` 15m

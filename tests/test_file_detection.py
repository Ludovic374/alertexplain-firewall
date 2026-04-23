# test_file_detection.py
"""
Script de démonstration — crée différents types de fichiers suspects
dans Downloads pour montrer que AlertExplain détecte les menaces fichiers.
"""
import os
import time
import random
import string

DOWNLOADS = os.path.expanduser("~\\Downloads")

def wait(msg, secs=3):
    print(f"  ⏳ {msg} ({secs}s)...")
    time.sleep(secs)

def random_name(ext):
    prefix = ''.join(random.choices(string.ascii_lowercase, k=6))
    return os.path.join(DOWNLOADS, f"test_{prefix}{ext}")

print("=" * 60)
print("  AlertExplain — Test de détection de fichiers")
print("=" * 60)
print(f"Dossier surveillé : {DOWNLOADS}")
print("Lance main.py avant ce script !\n")

# ── TEST 1 : Fichier texte normal (LOW risk) ───────────────────
print("[TEST 1] Fichier texte normal → FILE_NEW (LOW)")
path1 = random_name(".txt")
with open(path1, "w") as f:
    f.write("Ceci est un fichier texte normal.\n" * 10)
print(f"  Créé : {os.path.basename(path1)}")
wait("Attente détection", 4)

# ── TEST 2 : Double extension suspecte ────────────────────────
print("\n[TEST 2] Double extension .pdf.exe → FILE_RISK (HIGH)")
path2 = random_name(".pdf.exe")
with open(path2, "wb") as f:
    f.write(b"MZ" + b"\x00" * 100)   # Faux en-tête PE
print(f"  Créé : {os.path.basename(path2)}")
wait("Attente détection", 4)

# ── TEST 3 : Fichier avec entropie élevée (chiffré/compressé) ──
print("\n[TEST 3] Fichier haute entropie (données aléatoires) → FILE_RISK")
path3 = random_name(".bin")
with open(path3, "wb") as f:
    f.write(os.urandom(50000))   # 50KB de données aléatoires
print(f"  Créé : {os.path.basename(path3)}")
wait("Attente détection", 4)

# ── TEST 4 : Faux script PowerShell ───────────────────────────
print("\n[TEST 4] Script PowerShell suspect → FILE_RISK")
path4 = random_name(".ps1")
with open(path4, "w") as f:
    f.write("# Script de test AlertExplain\n")
    f.write("Invoke-WebRequest -Uri 'http://test.example.com'\n")
    f.write("Start-Process cmd.exe\n")
print(f"  Créé : {os.path.basename(path4)}")
wait("Attente détection", 4)

# ── TEST 5 : Nom suspect (password, crack) ────────────────────
print("\n[TEST 5] Fichier au nom suspect → FILE_RISK")
path5 = os.path.join(DOWNLOADS, "crack_password_2024.exe")
with open(path5, "wb") as f:
    f.write(b"MZ" + b"\x90" * 200)
print(f"  Créé : {os.path.basename(path5)}")
wait("Attente détection", 4)

# ── TEST 6 : Faux PDF normal ───────────────────────────────────
print("\n[TEST 6] Faux PDF (contenu PDF valide) → FILE_NEW (LOW)")
path6 = random_name(".pdf")
with open(path6, "wb") as f:
    f.write(b"%PDF-1.4\n1 0 obj\n<</Type /Catalog>>\nendobj\n%%EOF")
print(f"  Créé : {os.path.basename(path6)}")
wait("Attente détection", 4)

# ── Nettoyage ──────────────────────────────────────────────────
print("\n" + "=" * 60)
print("✅ Tests fichiers terminés !")
print("Vérifie le dashboard → onglet Fichiers")
print("URL : http://127.0.0.1:5000/dashboard")
print("=" * 60)

print("\nNettoyer les fichiers de test ? (o/n) : ", end="")
choice = input().strip().lower()
if choice == "o":
    for p in [path1, path2, path3, path4, path5, path6]:
        try:
            os.remove(p)
            print(f"  Supprimé : {os.path.basename(p)}")
        except Exception as e:
            print(f"  Erreur suppression {os.path.basename(p)}: {e}")
    print("✅ Nettoyage terminé !")
else:
    print("Fichiers conservés dans Downloads.")

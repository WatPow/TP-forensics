# Eval-forensics

# 🕵️ ANALYSE MEMOIRE – PARTIE 1

## MEMOIRE

### 1 - Indiquez le nom du profil volatility

Je n'ai pas utilisé Volatility2 mais Volatility3, il n'y a donc pas de "profil" car vol3 détecte automatiquement le profil

### 2 - Quel est le nom du processus malveillant et son PID ?

**Processus suspects identifiés dans le dump mémoire**

Après analyse du dump mémoire d’un ordinateur infecté par WannaCry, plusieurs processus suspects ont été identifiés :

1. **ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe**  
   - PID : 1692  
   - Exécutable principal de WannaCry  
   - Nom au format hexadécimal long  
   - Entropie élevée (8.00), suggérant un chiffrement ou packing  
   - Localisation : `C:\Users\Test-gic\Desktop\`

2. **@WanaDecryptor@.exe**  
   - PIDs : 3344, 3564, 3988  
   - Affiche l’interface de rançon  
   - Localisation : `C:\Users\Test-gic\Desktop\`

3. **taskhsvc.exe**  
   - PID : 1548  
   - Lancé par WanaDecryptor (PID 3344)  
   - Fait partie de l’infrastructure du ransomware  
   - Localisation : `C:\Users\Test-gic\Desktop\TaskData\Tor\`

---

### 3 - Le malware s’est connecté à ses probables C2 en HTTPS. Quelles sont leurs adresses IP ?

**Adresses IP identifiées à partir du dump mémoire analysé avec MemProcFR**  
Port utilisé : 443 (HTTPS)

1. **212.129.38.254:443**  
   - Connexion HTTPS établie par `taskhsvc.exe` (PID 1548)  
   - État : CLOSED

2. **199.254.238.52:443**  
   - Connexion HTTPS établie par `taskhsvc.exe` (PID 1548)  
   - État : CLOSED

Ces connexions ont été établies par un binaire situé dans `TaskData\Tor\`, ce qui laisse penser à une utilisation de Tor.  
Après une recherche OSINT, je confirme que ces adresses IP sont bien reconnues comme des IOCs de WannaCry.

---

### 4 - Une persistance est présente dans la base de registre

Commande utilisée :

```
"C:\Users\cyber\Desktop\MEMORY\VolatilityWorkbench\vol.exe" -f "E:\EVAL\Partie Memoire\eval_dump.raw" windows.registry.hivelist.HiveList 
```
Offset	FileFullPath	File output
0xf8a0006d0010	\Device\HarddiskVolume1\Boot\BCD	Disabled
0xf8a0006d2010	\SystemRoot\System32\Config\SOFTWARE	Disabled
0xf8a0008bd010	\SystemRoot\System32\Config\SECURITY	Disabled
0xf8a00091a420	\SystemRoot\System32\Config\SAM	Disabled
0xf8a0009d3010	\??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT	Disabled
0xf8a000a58420	\??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT	Disabled
0xf8a000e03010	\??\C:\Users\Test-gic\ntuser.dat	Disabled

#### Recherche dans la ruche avec l'offset

```
"C:\Users\cyber\Desktop\MEMORY\VolatilityWorkbench\vol.exe" -f "E:\EVAL\Partie Memoire\eval_dump.raw" windows.registry.printkey.PrintKey --offset 0xf8a000e03010 --key Software\Microsoft\Windows\CurrentVersion\Run 
```
Last Write Time	Hive Offset	Type	Key	Name	Data	Volatile
2019-03-28 13:40:01.000000 UTC	0xf8a000e03010	REG_SZ	\??\C:\Users\Test-gic\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Run	vszfzinpcporhed956	""C:\Users\Test-gic\Desktop\tasksche.exe""	False

---

### 5 - Des traces .onion sont présentes dans le malware. Quelles sont les deux adresses ?

Recherche avec PowerShell :

```
Get-ChildItem -Recurse -File | Select-String -Pattern "\b[a-z2-7]{16,56}\.onion\b"
```

**Adresses détectées :**
- 57g7spgrzlojinas.onion  
- cwwnhwhlz52maqm7.onion  

---

# PARTIE 2 : MFT

### Outil utilisé : Script batch perso

```batch
@echo off
setlocal
set MFT_FILE=%~1
if "%MFT_FILE%"=="" (
    echo [ERREUR] Veuillez glisser-deposer un fichier $MFT ou passer son chemin en argument.
    echo Exemple : analyze_mft.bat C:\forensics\$MFT
    pause
    exit /b
)
set OUTPUT_DIR=output
if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
)
MFTECmd.exe -f "%MFT_FILE%" --csv "%OUTPUT_DIR%"
echo.
echo [OK] Analyse terminee. Resultats dans le dossier : %OUTPUT_DIR%
pause
```

### Méthodologie :

- Glisser-déposer du fichier `$MFT` sur le `.bat`  
- Un fichier CSV est généré  
- Analyse dans Timeline Explorer avec filtres :

  - **Desktop** → Fichiers présents sur le bureau  
  - **Download** → Fichiers téléchargés  

### Fichiers trouvés :

- **Tor Browser** → Date inconnue  
- **WinUpdate.exe** → 28/11/2018 à 10:31:53  

---

# PARTIE 3

### 8 - Le Magic number est 4D5A

- Typique du format PE (Portable Executable)

---

### 9 - Le langage utilisé est C#

- Visible dans les headers via PIE

---

### 10 - L’entropie du programme est de 5.06

- On peut considérer qu’il **n’est pas packé**

---

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

**Adresses IP identifiées à partir du dump mémoire analysé avec MemProcFS**
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

```
Offset	FileFullPath	File output
0xf8a0006d0010	\Device\HarddiskVolume1\Boot\BCD	Disabled
0xf8a0006d2010	\SystemRoot\System32\Config\SOFTWARE	Disabled
0xf8a0008bd010	\SystemRoot\System32\Config\SECURITY	Disabled
0xf8a00091a420	\SystemRoot\System32\Config\SAM	Disabled
0xf8a0009d3010	\??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT	Disabled
0xf8a000a58420	\??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT	Disabled
0xf8a000e03010	\??\C:\Users\Test-gic\ntuser.dat	Disabled
```

#### Recherche dans la ruche avec l'offset

```
"C:\Users\cyber\Desktop\MEMORY\VolatilityWorkbench\vol.exe" -f "E:\EVAL\Partie Memoire\eval_dump.raw" windows.registry.printkey.PrintKey --offset 0xf8a000e03010 --key Software\Microsoft\Windows\CurrentVersion\Run 
```

```
Last Write Time	Hive Offset	Type	Key	Name	Data	Volatile
2019-03-28 13:40:01.000000 UTC	0xf8a000e03010	REG_SZ	\??\C:\Users\Test-gic\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Run	vszfzinpcporhed956	""C:\Users\Test-gic\Desktop\tasksche.exe""	False
```

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

- **Tor Browser** → 28/11/2018 à 10:32:11  
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

### 11 - Que fait le malware ?

- J'ai utilisé Procmon dans une VM et j'ai ajouté un filtre sur le malware.exe pour capter uniquements ces modifications
Je l'ai claqué dans la VM R.I.P WindowsFlare mais voici ce que j'ai pu trouver (c'est pas exhaustif car il y a des centaines de Création/Modifications etc.)

#### 🔍 Type d’activité détectée

- 1 démarrage de processus  
- 21 créations de thread  
- 96 chargements de bibliothèques  
- 743 accès/écritures sur des fichiers  
- 15 modifications du registre  

#### 📁 Fichiers accédés ou créés

- `C:\Windows\System32\OpenWith.exe` : 30 fois  
- `C:\Users\aripotter\Desktop\EVAL\Partie Malware\ProcessMonitor\malware.exe` : 17 fois  
- `C:\Windows\System32\fr-FR\tzres.dll.mui` : 16 fois  
- `C:\Windows\Microsoft.NET\assembly\GAC_64\System.Transactions\v4.0_4.0.0.0__b77a5c561934e089\System.Transactions.dll` : 15 fois  
- `C:\Windows\Microsoft.NET\assembly\GAC_64\System.Data\v4.0_4.0.0.0__b77a5c561934e089\System.Data.dll` : 15 fois  

#### 🧠 Modifications du registre

- `HKCU\Software\Classes\Local Settings` : 2 écriture(s)  
- `HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing` : 1 écriture(s)  
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace` : 1 écriture(s)  
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace` : 1 écriture(s)  
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders` : 1 écriture(s)  

#### 🧾 Conclusion préliminaire

- Le binaire tente d’écrire dans le registre, possiblement pour établir une persistance.  
- Des fichiers sont créés dans les chemins système ou de configuration, ce qui peut indiquer une activité malveillante.  
- Le programme charge intensivement des bibliothèques, ce qui peut indiquer un packer ou du code injecté dynamiquement.  

#### 🧪 Analyse de `malware.exe` — Timeline condensée

- **10:47:44** – `Process Start` on `` → *SUCCESS*  
  _Parent PID: 4628, Command line: "C:\Users\aripotter\Desktop\EVAL\Partie Malware\ProcessMonitor\malware.exe" , Current directory: C:\Users\aripotter\Desktop\EVAL\Partie Malware\ProcessMonitor\, Environment: 
;	=::=::\
;	ALLUSERSPROFILE=C:\ProgramData
;	APPDATA=C:\Users\aripotter\AppData\Roaming
;	ChocolateyInstall=C:\ProgramData\chocolatey
;	ChocolateyLastPathUpdate=133886679338391017
;	ChocolateyToolsLocation=C:\Tools
;	CommonProgramFiles=C:\Program Files\Common Files
;	CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
;	CommonProgramW6432=C:\Program Files\Common Files
;	COMPUTERNAME=FLARE
;	ComSpec=C:\Windows\system32\cmd.exe
;	DriverData=C:\Windows\System32\Drivers\DriverData
;	HOMEDRIVE=C:
;	HOMEPATH=\Users\aripotter
;	JAVA_HOME=C:\Program Files\OpenJDK\jdk-21.0.1
;	JDK_HOME=C:\Program Files\OpenJDK\jdk-21.0.1
;	LOCALAPPDATA=C:\Users\aripotter\AppData\Local
;	LOGONSERVER=\\FLARE
;	NUMBER_OF_PROCESSORS=3
;	OneDrive=C:\Users\aripotter\OneDrive
;	OS=Windows_NT
;	Path=C:\ProgramData\chocolatey\bin;C:\Python310\Scripts\;C:\Python310\;C:\ProgramData\Boxstarter;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\ProgramData\chocolatey\bin;C:\Program Files\010 Editor;C:\Program Files\OpenJDK\jdk-21.0.1\bin;C:\Tools\apktool;C:\Users\aripotter\AppData\Local\Microsoft\WindowsApps;C:\Program Files\BinDiff\bin;C:\Tools\Beta-cbb1d5c32d02b4e07128a197c8b8fb6ea597916a;C:\Tools\DidierStevensSuite-8190354314d6f42c9ddc477a795029dc446176c5;C:\Program Files\dotnet\;C:\Program Files (x86)\dotnet\;C:\Program Files\Git\cmd;C:\Program Files\nodejs\;C:\Program Files\Microsoft VS Code\bin;C:\Users\aripotter\AppData\Local\Microsoft\WindowsApps;;C:\Tools\Cmder;C:\Users\aripotter\AppData\Roaming\npm;C:\Program Files (x86)\Nmap;C:\Users\aripotter\.dotnet\tools;C:\Tools\sysinternals
;	PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.PY;.PYW
;	PROCESSOR_ARCHITECTURE=AMD64
;	PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 94 Stepping 3, GenuineIntel
;	PROCESSOR_LEVEL=6
;	PROCESSOR_REVISION=5e03
;	ProgramData=C:\ProgramData
;	ProgramFiles=C:\Program Files
;	ProgramFiles(x86)=C:\Program Files (x86)
;	ProgramW6432=C:\Program Files
;	PROMPT=FLARE-VM$S$d$s$t$_$p$+$g
;	PSModulePath=C:\Users\aripotter\Documents\WindowsPowerShell\Modules
;	PUBLIC=C:\Users\Public
;	RAW_TOOLS_DIR=C:\Tools
;	SESSIONNAME=Console
;	SystemDrive=C:
;	SystemRoot=C:\Windows
;	TEMP=C:\Users\ARIPOT~1\AppData\Local\Temp
;	TMP=C:\Users\ARIPOT~1\AppData\Local\Temp
;	TOOL_LIST_DIR=C:\Users\aripotter\Desktop\Tools
;	USERDOMAIN=FLARE
;	USERDOMAIN_ROAMINGPROFILE=FLARE
;	USERNAME=aripotter
;	USERPROFILE=C:\Users\aripotter
;	VMname=FLARE-VM
;	VM_COMMON_DIR=C:\ProgramData\_VM
;	windir=C:\Windows_
- **10:47:44** – `Thread Create` executed 6 times (e.g., ``) → *SUCCESS*  
  _Thread ID: 3788_
- **10:47:44** – `Load Image` executed 38 times (e.g., `C:\Users\aripotter\Desktop\EVAL\Partie Malware\ProcessMonitor\malware.exe`) → *SUCCESS*  
  _Image Base: 0x2c0000, Image Size: 0x8000_
- **10:47:44** – `CreateFile` executed 144 times (e.g., `C:\Windows\Prefetch\MALWARE.EXE-F39D19D6.pf`) → *NAME NOT FOUND*  
  _Desired Access: Generic Read, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: None, AllocationSize: n/a_
- **10:47:44** – `RegOpenKey` executed 205 times (e.g., `HKLM\System\CurrentControlSet\Control\Session Manager`) → *REPARSE*  
  _Desired Access: Query Value_
- **10:47:44** – `RegQueryValue` executed 91 times (e.g., `HKLM\System\CurrentControlSet\Control\Session Manager\RaiseExceptionOnPossibleDeadlock`) → *NAME NOT FOUND*  
  _Length: 80_
- **10:47:44** – `RegCloseKey` executed 77 times (e.g., `HKLM\System\CurrentControlSet\Control\Session Manager`) → *SUCCESS*  
  __
- **10:47:44** – `QueryBasicInformationFile` executed 30 times (e.g., `C:\Windows\System32\mscoree.dll`) → *SUCCESS*  
  _CreationTime: 07/12/2019 11:10:05, LastAccessTime: 11/04/2025 10:47:10, LastWriteTime: 07/12/2019 11:10:05, ChangeTime: 09/04/2025 11:23:50, FileAttributes: A_
- **10:47:44** – `CloseFile` executed 122 times (e.g., `C:\Windows\System32\mscoree.dll`) → *SUCCESS*  
  __
- **10:47:44** – `CreateFileMapping` executed 52 times (e.g., `C:\Windows\System32\mscoree.dll`) → *FILE LOCKED WITH ONLY READERS*  
  _SyncType: SyncTypeCreateSection, PageProtection: PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE_
- **10:47:44** – `QuerySecurityFile` executed 13 times (e.g., `C:\Windows\System32\conhost.exe`) → *SUCCESS*  
  _Information: Label_
- **10:47:44** – `QueryNameInformationFile` executed 2 times (e.g., `C:\Windows\System32\conhost.exe`) → *SUCCESS*  
  _Name: \Windows\System32\conhost.exe_
- **10:47:44** – `Process Create` on `C:\Windows\System32\Conhost.exe` → *SUCCESS*  
  _PID: 3388, Command line: \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1_
- **10:47:44** – `ReadFile` executed 44 times (e.g., `C:\Windows\System32\mscoree.dll`) → *SUCCESS*  
  _Offset: 370 688, Length: 6 656, I/O Flags: Non-cached, Paging I/O, Synchronous Paging I/O, Priority: Normal_
- **10:47:44** – `QueryStandardInformationFile` executed 15 times (e.g., `C:\Windows\apppatch\sysmain.sdb`) → *SUCCESS*  
  _AllocationSize: 4 075 520, EndOfFile: 4 073 452, NumberOfLinks: 2, DeletePending: False, Directory: False_
- **10:47:44** – `RegQueryKey` executed 104 times (e.g., `HKLM`) → *SUCCESS*  
  _Query: HandleTags, HandleTags: 0x0_
- **10:47:44** – `RegEnumKey` executed 58 times (e.g., `HKLM\SOFTWARE\Microsoft\.NETFramework\policy`) → *SUCCESS*  
  _Index: 5, Name: v4.0_
- **10:47:44** – `RegEnumValue` executed 7 times (e.g., `HKLM\SOFTWARE\Microsoft\.NETFramework\policy\v4.0`) → *SUCCESS*  
  _Index: 0, Name: 30319, Type: REG_SZ, Length: 24, Data: 30319-30319_
- **10:47:44** – `QueryDirectory` executed 20 times (e.g., `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscoreei.dll`) → *SUCCESS*  
  _FileInformationClass: FileBothDirectoryInformation, Filter: mscoreei.dll, 2: mscoreei.dll_
- **10:47:44** – `RegSetInfoKey` executed 13 times (e.g., `HKLM\SOFTWARE\Microsoft\Fusion`) → *SUCCESS*  
  _KeySetInformationClass: KeySetHandleTagsInformation, Length: 0_
- **10:47:44** – `QueryNetworkOpenInformationFile` executed 37 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_64\mscorlib\v4.0_4.0.0.0__b77a5c561934e089\mscorlib.dll`) → *SUCCESS*  
  _CreationTime: 04/12/2023 04:40:29, LastAccessTime: 11/04/2025 10:45:42, LastWriteTime: 04/12/2023 04:40:29, ChangeTime: 09/04/2025 11:23:50, AllocationSize: 01/01/1601 02:00:00, EndOfFile: 01/01/1601 02:00:00, FileAttributes: A_
- **10:47:44** – `QueryInformationVolume` on `C:\Users\aripotter\Desktop\EVAL\Partie Malware\ProcessMonitor\malware.exe` → *SUCCESS*  
  _VolumeCreationTime: 09/04/2025 10:39:23, VolumeSerialNumber: 00E5-D6D9, SupportsObjects: True, VolumeLabel: _
- **10:47:44** – `QueryAllInformationFile` on `C:\Users\aripotter\Desktop\EVAL\Partie Malware\ProcessMonitor\malware.exe` → *BUFFER OVERFLOW*  
  _CreationTime: 11/04/2025 10:44:21, LastAccessTime: 11/04/2025 10:47:49, LastWriteTime: 17/03/2023 12:05:32, ChangeTime: 11/04/2025 10:44:31, FileAttributes: A, AllocationSize: 12 288, EndOfFile: 12 288_
- **10:47:45** – `RegOpenKey` executed 418 times (e.g., `HKLM\System\CurrentControlSet\Control\Nls\CustomLocale`) → *REPARSE*  
  _Desired Access: Read_
- **10:47:45** – `RegQueryValue` executed 440 times (e.g., `HKLM\System\CurrentControlSet\Control\Nls\CustomLocale\en-US`) → *NAME NOT FOUND*  
  _Length: 532_
- **10:47:45** – `RegCloseKey` executed 225 times (e.g., `HKLM\System\CurrentControlSet\Control\Nls\CustomLocale`) → *SUCCESS*  
  __
- **10:47:45** – `ReadFile` executed 122 times (e.g., `C:\Windows\assembly\NativeImages_v4.0.30319_64\System\7497aebfb6ef3f9995d6359fb147361f\System.ni.dll`) → *SUCCESS*  
  _Offset: 7 795 712, Length: 32 768, I/O Flags: Non-cached, Paging I/O, Synchronous Paging I/O, Priority: Normal_
- **10:47:45** – `RegQueryKey` executed 414 times (e.g., `HKLM`) → *SUCCESS*  
  _Query: HandleTags, HandleTags: 0x0_
- **10:47:45** – `CreateFile` executed 321 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`) → *SUCCESS*  
  _Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened_
- **10:47:45** – `QueryNetworkOpenInformationFile` executed 49 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`) → *SUCCESS*  
  _CreationTime: 04/12/2023 04:49:00, LastAccessTime: 11/04/2025 10:46:02, LastWriteTime: 04/12/2023 04:49:00, ChangeTime: 09/04/2025 10:41:15, AllocationSize: 01/01/1601 02:00:00, EndOfFile: 01/01/1601 02:00:00, FileAttributes: A_
- **10:47:45** – `CloseFile` executed 247 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`) → *SUCCESS*  
  __
- **10:47:45** – `QueryBasicInformationFile` executed 83 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`) → *SUCCESS*  
  _CreationTime: 04/12/2023 04:49:00, LastAccessTime: 11/04/2025 10:46:02, LastWriteTime: 04/12/2023 04:49:00, ChangeTime: 09/04/2025 10:41:15, FileAttributes: A_
- **10:47:45** – `CreateFileMapping` executed 98 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`) → *FILE LOCKED WITH ONLY READERS*  
  _SyncType: SyncTypeCreateSection, PageProtection: PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE_
- **10:47:45** – `QuerySecurityFile` executed 2 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`) → *BUFFER OVERFLOW*  
  _Information: Owner, Group, DACL_
- **10:47:45** – `QueryStandardInformationFile` executed 42 times (e.g., `C:\Windows\System32\winnlsres.dll`) → *SUCCESS*  
  _AllocationSize: 20 480, EndOfFile: 19 968, NumberOfLinks: 2, DeletePending: False, Directory: False_
- **10:47:45** – `QueryDirectory` executed 44 times (e.g., `C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P1706cafe#\*`) → *SUCCESS*  
  _FileInformationClass: FileBothDirectoryInformation, Filter: *, 2: ._
- **10:47:45** – `Load Image` executed 29 times (e.g., `C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P1706cafe#\9e452ff159abd6e54f4c24f64c4a4f10\Microsoft.PowerShell.Commands.Diagnostics.ni.dll`) → *SUCCESS*  
  _Image Base: 0x7fff8aed0000, Image Size: 0x62000_
- **10:47:45** – `QueryInformationVolume` executed 3 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation.Resources\v4.0_3.0.0.0_fr_31bf3856ad364e35\System.Management.Automation.Resources.dll`) → *SUCCESS*  
  _VolumeCreationTime: 09/04/2025 10:39:23, VolumeSerialNumber: 00E5-D6D9, SupportsObjects: True, VolumeLabel: _
- **10:47:45** – `QueryAllInformationFile` executed 3 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation.Resources\v4.0_3.0.0.0_fr_31bf3856ad364e35\System.Management.Automation.Resources.dll`) → *BUFFER OVERFLOW*  
  _CreationTime: 04/12/2023 04:48:50, LastAccessTime: 09/04/2025 12:05:06, LastWriteTime: 04/12/2023 04:48:50, ChangeTime: 09/04/2025 10:41:16, FileAttributes: A, AllocationSize: 540 672, EndOfFile: 539 136_
- **10:47:45** – `RegSetInfoKey` executed 19 times (e.g., `HKLM\SOFTWARE\Microsoft\Cryptography`) → *SUCCESS*  
  _KeySetInformationClass: KeySetHandleTagsInformation, Length: 0_
- **10:47:45** – `WriteFile` executed 2 times (e.g., `C:\Users\aripotter\AppData\Local\Temp\__PSScriptPolicyTest_jry5t0ew.ue4.ps1`) → *SUCCESS*  
  _Offset: 0, Length: 60, Priority: Normal_
- **10:47:45** – `DeviceIoControl` executed 6 times (e.g., `C:\Users\aripotter\AppData\Local\Temp\__PSScriptPolicyTest_jry5t0ew.ue4.ps1`) → *INVALID PARAMETER*  
  _Control: IOCTL_MOUNTDEV_QUERY_DEVICE_NAME_
- **10:47:45** – `FileSystemControl` executed 10 times (e.g., `C:\Users\aripotter\AppData\Local\Temp`) → *NOT REPARSE POINT*  
  _Control: FSCTL_GET_REPARSE_POINT_
- **10:47:45** – `QueryNameInformationFile` on `C:\Users\aripotter\AppData\Local\Temp\__PSScriptPolicyTest_jry5t0ew.ue4.ps1` → *SUCCESS*  
  _Name: \Users\aripotter\AppData\Local\Temp\__PSScriptPolicyTest_jry5t0ew.ue4.ps1_
- **10:47:45** – `RegCreateKey` on `HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing` → *SUCCESS*  
  _Desired Access: Read, Disposition: REG_OPENED_EXISTING_KEY_
- **10:47:45** – `Thread Create` executed 7 times (e.g., ``) → *SUCCESS*  
  _Thread ID: 6700_
- **10:47:45** – `RegEnumKey` executed 80 times (e.g., `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllIsMyFileType2`) → *SUCCESS*  
  _Index: 0, Name: {000C10F1-0000-0000-C000-000000000046}_
- **10:47:45** – `RegEnumValue` executed 129 times (e.g., `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllIsMyFileType2\{000C10F1-0000-0000-C000-000000000046}`) → *SUCCESS*  
  _Index: 0, Name: Dll, Type: REG_SZ, Length: 62, Data: C:\Windows\System32\MSISIP.DLL_
- **10:47:45** – `QueryAttributeTagFile` executed 2 times (e.g., `C:\Users\aripotter\AppData\Local\Temp\__PSScriptPolicyTest_jry5t0ew.ue4.ps1`) → *SUCCESS*  
  _Attributes: A, ReparseTag: 0x0_
- **10:47:45** – `SetDispositionInformationEx` executed 2 times (e.g., `C:\Users\aripotter\AppData\Local\Temp\__PSScriptPolicyTest_jry5t0ew.ue4.ps1`) → *SUCCESS*  
  _Flags: FILE_DISPOSITION_DELETE, FILE_DISPOSITION_POSIX_SEMANTICS, FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK_
- **10:47:46** – `RegQueryKey` executed 1117 times (e.g., `HKLM`) → *SUCCESS*  
  _Query: HandleTags, HandleTags: 0x0_
- **10:47:46** – `RegOpenKey` executed 863 times (e.g., `HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft Strong Cryptographic Provider`) → *SUCCESS*  
  _Desired Access: Read_
- **10:47:46** – `RegQueryValue` executed 611 times (e.g., `HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft Strong Cryptographic Provider\Type`) → *SUCCESS*  
  _Type: REG_DWORD, Length: 4, Data: 1_
- **10:47:46** – `RegSetInfoKey` executed 5 times (e.g., `HKLM\SOFTWARE\Microsoft\Cryptography`) → *SUCCESS*  
  _KeySetInformationClass: KeySetHandleTagsInformation, Length: 0_
- **10:47:46** – `RegCloseKey` executed 317 times (e.g., `HKLM\SOFTWARE\Microsoft\Cryptography`) → *SUCCESS*  
  __
- **10:47:46** – `CreateFile` executed 221 times (e.g., `C:\Users\aripotter\Documents`) → *SUCCESS*  
  _Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened_
- **10:47:46** – `QueryBasicInformationFile` executed 83 times (e.g., `C:\Users\aripotter\Documents`) → *SUCCESS*  
  _CreationTime: 09/04/2025 09:49:44, LastAccessTime: 11/04/2025 10:45:58, LastWriteTime: 09/04/2025 10:36:13, ChangeTime: 09/04/2025 10:36:13, FileAttributes: RD_
- **10:47:46** – `CloseFile` executed 145 times (e.g., `C:\Users\aripotter\Documents`) → *SUCCESS*  
  __
- **10:47:46** – `ReadFile` executed 116 times (e.g., `C:\Windows\assembly\NativeImages_v4.0.30319_64\mscorlib\4bc5e5252873c08797895d5b6fe6ddfd\mscorlib.ni.dll`) → *SUCCESS*  
  _Offset: 4 108 800, Length: 4 096, I/O Flags: Non-cached, Paging I/O, Synchronous Paging I/O, Priority: Normal_
- **10:47:46** – `QueryNetworkOpenInformationFile` executed 13 times (e.g., `C:\Windows\System32\WindowsPowerShell\v1.0`) → *SUCCESS*  
  _CreationTime: 07/12/2019 11:14:52, LastAccessTime: 11/04/2025 10:47:50, LastWriteTime: 04/12/2023 04:53:31, ChangeTime: 09/04/2025 10:43:03, AllocationSize: 01/01/1601 02:00:00, EndOfFile: 01/01/1601 02:00:00, FileAttributes: D_
- **10:47:46** – `QueryInformationVolume` executed 5 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Numerics\v4.0_4.0.0.0__b77a5c561934e089\System.Numerics.dll`) → *SUCCESS*  
  _VolumeCreationTime: 09/04/2025 10:39:23, VolumeSerialNumber: 00E5-D6D9, SupportsObjects: True, VolumeLabel: _
- **10:47:46** – `QueryAllInformationFile` executed 4 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Numerics\v4.0_4.0.0.0__b77a5c561934e089\System.Numerics.dll`) → *BUFFER OVERFLOW*  
  _CreationTime: 07/12/2019 11:10:37, LastAccessTime: 11/04/2025 10:46:02, LastWriteTime: 07/12/2019 11:10:37, ChangeTime: 09/04/2025 12:00:40, FileAttributes: A, AllocationSize: 143 360, EndOfFile: 139 848_
- **10:47:46** – `CreateFileMapping` executed 84 times (e.g., `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Numerics\v4.0_4.0.0.0__b77a5c561934e089\System.Numerics.dll`) → *FILE LOCKED WITH ONLY READERS*  
  _SyncType: SyncTypeCreateSection, PageProtection: PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE_
- **10:47:46** – `QueryDirectory` executed 2 times (e.g., `C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Transactions\*`) → *SUCCESS*  
  _FileInformationClass: FileBothDirectoryInformation, Filter: *, 2: ._
- **10:47:46** – `QueryStandardInformationFile` executed 20 times (e.g., `C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Transactions\f96c5f801b4566004098fbfd9d38cafc\System.Transactions.ni.dll.aux`) → *SUCCESS*  
  _AllocationSize: 4 096, EndOfFile: 924, NumberOfLinks: 1, DeletePending: False, Directory: False_
- **10:47:46** – `Load Image` executed 25 times (e.g., `C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Transactions\f96c5f801b4566004098fbfd9d38cafc\System.Transactions.ni.dll`) → *SUCCESS*  
  _Image Base: 0x7fff68b60000, Image Size: 0xdb000_
- **10:47:46** – `RegEnumKey` executed 69 times (e.g., `HKLM\System\CurrentControlSet\Services\EventLog`) → *SUCCESS*  
  _Index: 0, Name: Application_
- **10:47:46** – `QueryNameInformationFile` executed 3 times (e.g., `C:\`) → *SUCCESS*  
  _Name: \_
- **10:47:46** – `QueryAttributeInformationVolume` on `C:\` → *SUCCESS*  
  _FileSystemAttributes: Case Preserved, Case Sensitive, Unicode, ACLs, Compression, Named Streams, EFS, Object IDs, Reparse Points, Sparse Files, Quotas, Transactions, 0x3c00600, MaximumComponentNameLength: 255, FileSystemName: NTFS_
- **10:47:46** – `Thread Create` executed 8 times (e.g., ``) → *SUCCESS*  
  _Thread ID: 5820_
- **10:47:46** – `WriteFile` executed 2 times (e.g., `C:\Users\aripotter\Desktop\PS_Transcripts\20250411\PowerShell_transcript.FLARE.2bA+fJc5.20250411104750.txt`) → *SUCCESS*  
  _Offset: 0, Length: 3, Priority: Normal_
- **10:47:46** – `RegEnumValue` executed 107 times (e.g., `HKLM\System\CurrentControlSet\Control\Session Manager\Environment`) → *SUCCESS*  
  _Index: 0, Name: ComSpec, Type: REG_EXPAND_SZ, Length: 60, Data: %SystemRoot%\system32\cmd.exe_
- **10:47:46** – `RegCreateKey` executed 4 times (e.g., `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace`) → *SUCCESS*  
  _Desired Access: Notify, Disposition: REG_OPENED_EXISTING_KEY_
- **10:47:46** – `QuerySizeInformationVolume` executed 2 times (e.g., `C:\Windows\System32`) → *SUCCESS*  
  _TotalAllocationUnits: 20 971 007, AvailableAllocationUnits: 12 678 410, SectorsPerAllocationUnit: 8, BytesPerSector: 512_
- **10:47:46** – `RegSetValue` executed 2 times (e.g., `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SlowContextMenuEntries`) → *SUCCESS*  
  _Type: REG_BINARY, Length: 100, Data: 10 90 1E F8 A4 6E CE 11 A7 FF 00 AA 00 3C A9 F6_
- **10:47:47** – `CreateFile` executed 57 times (e.g., `C:\Users\aripotter`) → *NAME COLLISION*  
  _Desired Access: Read Data/List Directory, Synchronize, Disposition: Create, Options: Directory, Synchronous IO Non-Alert, Open Reparse Point, Attributes: N, ShareMode: Read, Write, AllocationSize: 0_
- **10:47:47** – `QueryBasicInformationFile` executed 28 times (e.g., `C:\Users\aripotter`) → *SUCCESS*  
  _CreationTime: 09/04/2025 09:49:44, LastAccessTime: 11/04/2025 10:47:51, LastWriteTime: 09/04/2025 14:58:23, ChangeTime: 09/04/2025 14:58:23, FileAttributes: D_
- **10:47:47** – `CloseFile` executed 61 times (e.g., `C:\Users\aripotter`) → *SUCCESS*  
  __
- **10:47:47** – `RegQueryKey` executed 1085 times (e.g., `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache`) → *SUCCESS*  
  _Query: HandleTags, HandleTags: 0x0_
- **10:47:47** – `RegOpenKey` executed 695 times (e.g., `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies`) → *SUCCESS*  
  _Desired Access: Query Value, Set Value, Create Sub Key, Enumerate Sub Keys_
- **10:47:47** – `RegSetValue` executed 6 times (e.g., `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies\CachePrefix`) → *SUCCESS*  
  _Type: REG_SZ, Length: 16, Data: Cookie:_
- **10:47:47** – `RegQueryValue` executed 375 times (e.g., `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies\CacheVersion`) → *SUCCESS*  
  _Type: REG_DWORD, Length: 4, Data: 1_
- **10:47:47** – `RegCloseKey` executed 233 times (e.g., `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies`) → *SUCCESS*  
  __
- **10:47:47** – `ReadFile` executed 52 times (e.g., `C:\Windows\System32\iertutil.dll`) → *SUCCESS*  
  _Offset: 1 546 752, Length: 4 096, I/O Flags: Non-cached, Paging I/O, Synchronous Paging I/O, Priority: Normal_
- **10:47:47** – `CreateFileMapping` executed 32 times (e.g., `C:\Windows\System32\OneCoreUAPCommonProxyStub.dll`) → *FILE LOCKED WITH ONLY READERS*  
  _SyncType: SyncTypeCreateSection, PageProtection: PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE_
- **10:47:47** – `Load Image` executed 4 times (e.g., `C:\Windows\System32\OneCoreUAPCommonProxyStub.dll`) → *SUCCESS*  
  _Image Base: 0x7fff9a860000, Image Size: 0x7d0000_
- **10:47:47** – `RegSetInfoKey` executed 7 times (e.g., `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager`) → *SUCCESS*  
  _KeySetInformationClass: KeySetHandleTagsInformation, Length: 0_
- **10:47:47** – `RegCreateKey` executed 2 times (e.g., `HKCU\Software\Classes\Local Settings`) → *SUCCESS*  
  _Desired Access: Maximum Allowed, Granted Access: All Access, Disposition: REG_OPENED_EXISTING_KEY_
- **10:47:47** – `RegEnumKey` executed 2 times (e.g., `HKCR\Drive\shellex\FolderExtensions`) → *SUCCESS*  
  _Index: 0, Name: {fbeb8a05-beee-4442-804e-409d6c4515e9}_
- **10:47:47** – `FileSystemControl` executed 2 times (e.g., `C:\Windows\System32\OpenWith.exe`) → *CANCELLED*  
  _Control: FSCTL_REQUEST_OPLOCK_
- **10:47:47** – `QueryStandardInformationFile` executed 4 times (e.g., `C:\Program Files\WindowsApps\Microsoft.LanguageExperiencePackfr-FR_19041.80.268.0_neutral__8wekyb3d8bbwe\Windows\System32\fr-FR\OpenWith.exe.mui`) → *SUCCESS*  
  _AllocationSize: 16 384, EndOfFile: 13 368, NumberOfLinks: 1, DeletePending: False, Directory: False_
- **10:47:47** – `QuerySecurityFile` executed 8 times (e.g., `C:\Windows\System32\OpenWith.exe`) → *BUFFER OVERFLOW*  
  _Information: Owner, Group, DACL_
- **10:47:47** – `QueryNetworkOpenInformationFile` executed 5 times (e.g., `C:\Windows\SysWOW64\propsys.dll`) → *SUCCESS*  
  _CreationTime: 04/12/2023 04:47:46, LastAccessTime: 11/04/2025 10:46:07, LastWriteTime: 04/12/2023 04:47:46, ChangeTime: 09/04/2025 10:41:07, AllocationSize: 01/01/1601 02:00:00, EndOfFile: 01/01/1601 02:00:00, FileAttributes: A_
- **10:47:47** – `Thread Exit` executed 21 times (e.g., ``) → *SUCCESS*  
  _Thread ID: 3076, User Time: 0.0000000, Kernel Time: 0.0000000_
- **10:47:47** – `WriteFile` executed 4 times (e.g., `C:\Users\aripotter\Desktop\PS_Transcripts\20250411\PowerShell_transcript.FLARE.2bA+fJc5.20250411104750.txt`) → *SUCCESS*  
  _Offset: 672, Length: 24_
- **10:47:47** – `Process Exit` on `` → *SUCCESS*  
  _Exit Status: 0, User Time: 0.4531250 seconds, Kernel Time: 0.8437500 seconds, Private Bytes: 52 830 208, Peak Private Bytes: 53 198 848, Working Set: 65 912 832, Peak Working Set: 66 289 664_
  
---


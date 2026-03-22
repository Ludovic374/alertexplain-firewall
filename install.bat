@echo off
:: ============================================================
:: AlertExplain Firewall - Installateur Windows
:: Lancer ce fichier en tant qu'ADMINISTRATEUR
:: ============================================================

setlocal EnableDelayedExpansion

echo.
echo  =====================================================
echo   AlertExplain Firewall - Installation
echo  =====================================================
echo.

:: --- Vérification droits admin ---
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] Lance ce script en tant qu'ADMINISTRATEUR.
    echo Clic droit sur install.bat ^> "Executer en tant qu'administrateur"
    pause
    exit /b 1
)

:: --- Répertoire du script ---
set "BASE_DIR=%~dp0"
cd /d "%BASE_DIR%"
echo [INFO] Repertoire : %BASE_DIR%

:: --- Python ---
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] Python introuvable dans le PATH.
    echo Installe Python 3.10+ depuis https://python.org
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [INFO] %PYVER% detecte.

:: --- pip install des dependances ---
echo.
echo [STEP 1/4] Installation des dependances Python...
pip install scapy flask requests watchdog plyer pywin32 --quiet
if %errorLevel% neq 0 (
    echo [ERREUR] pip install a echoue. Verifie ta connexion internet.
    pause
    exit /b 1
)
echo [OK] Dependances installees.

:: --- Npcap (optionnel - nécessaire pour scapy sur Windows) ---
echo.
echo [STEP 2/4] Verification Npcap...
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARN] Npcap n'est pas installe. Scapy en aura besoin pour capturer des paquets.
    echo        Telecharge-le sur : https://npcap.com/#download
    echo        Installe-le avec l'option "Install Npcap in WinPcap API-compatible Mode"
    echo.
    set /p INSTALL_NPCAP="Continuer sans Npcap ? (o/n) : "
    if /i "!INSTALL_NPCAP!" neq "o" (
        echo Installation annulee.
        pause
        exit /b 1
    )
) else (
    echo [OK] Npcap detecte.
)

:: --- Variables d'environnement (optionnel) ---
echo.
echo [STEP 3/4] Configuration des variables d'environnement...
echo.
echo    VT_API_KEY  : cle VirusTotal (optionnel, gratuite sur virustotal.com)
echo    API_SECRET  : secret pour l'API Flask (recommande)
echo.
set /p VT_KEY="   VT_API_KEY (Entree pour ignorer) : "
set /p API_SEC="   API_SECRET  (Entree pour ignorer) : "

if not "!VT_KEY!"=="" (
    setx VT_API_KEY "!VT_KEY!" /M >nul
    echo [OK] VT_API_KEY definie.
)
if not "!API_SEC!"=="" (
    setx API_SECRET "!API_SEC!" /M >nul
    echo [OK] API_SECRET definie.
)

:: --- Installation + démarrage du service ---
echo.
echo [STEP 4/4] Installation du service Windows...

:: Arrêter + supprimer si déjà présent
sc query AlertExplainFirewall >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] Service existant detecte. Suppression...
    python service.py stop  >nul 2>&1
    timeout /t 2 /nobreak >nul
    python service.py remove >nul 2>&1
    timeout /t 2 /nobreak >nul
)

python service.py install
if %errorLevel% neq 0 (
    echo [ERREUR] Installation du service echouee.
    pause
    exit /b 1
)
echo [OK] Service installe.

python service.py start
if %errorLevel% neq 0 (
    echo [WARN] Demarrage du service echoue. Verifie les logs dans logs\service.log
) else (
    echo [OK] Service demarre.
)

:: --- Résumé ---
echo.
echo  =====================================================
echo   Installation terminee !
echo  =====================================================
echo.
echo   Dashboard : http://127.0.0.1:5000/dashboard
echo   Logs      : %BASE_DIR%logs\
echo.
echo   Commandes utiles :
echo     python service.py start   - Demarrer
echo     python service.py stop    - Arreter
echo     python service.py restart - Redemarrer
echo     python service.py remove  - Desinstaller
echo     python service.py status  - Statut
echo.
pause

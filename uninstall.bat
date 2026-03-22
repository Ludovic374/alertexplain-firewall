@echo off
:: ============================================================
:: AlertExplain Firewall - Désinstallateur
:: Lancer en tant qu'ADMINISTRATEUR
:: ============================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] Lance ce script en tant qu'ADMINISTRATEUR.
    pause
    exit /b 1
)

cd /d "%~dp0"

echo.
echo  Desinstallation du service AlertExplain Firewall...
echo.

python service.py stop    >nul 2>&1
timeout /t 2 /nobreak     >nul
python service.py remove

echo.
echo [OK] Service supprime.
echo.
echo Les fichiers du projet et les logs ne sont PAS supprimes.
echo Supprime manuellement le dossier si necessaire.
echo.
pause

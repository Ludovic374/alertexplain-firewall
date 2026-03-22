# service.py
"""
Service Windows pour AlertExplain Firewall.
Installe et gère main.py + app.py comme un service Windows natif.

Installation :
    python service.py install
    python service.py start

Désinstallation :
    python service.py stop
    python service.py remove

Debug (sans service, dans le terminal) :
    python service.py debug
"""

import sys
import os
import subprocess
import time
import logging
from pathlib import Path

import win32serviceutil
import win32service
import win32event
import servicemanager

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SERVICE_NAME    = "AlertExplainFirewall"
SERVICE_DISPLAY = "AlertExplain Host Firewall"
SERVICE_DESC    = "Surveillance réseau + fichiers, IPS/IDS, VirusTotal. AlertExplain."

BASE_DIR    = Path(__file__).parent.resolve()
PYTHON_EXE  = sys.executable          # même python que celui qui installe le service
MAIN_PY     = BASE_DIR / "main.py"
APP_PY      = BASE_DIR / "app.py"
LOG_DIR     = BASE_DIR / "logs"
LOG_FILE    = LOG_DIR / "service.log"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging():
    LOG_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Service class
# ---------------------------------------------------------------------------

class AlertExplainService(win32serviceutil.ServiceFramework):
    _svc_name_         = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY
    _svc_description_  = SERVICE_DESC

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event  = win32event.CreateEvent(None, 0, 0, None)
        self.processes   = []   # [proc_main, proc_app]
        _setup_logging()

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def SvcStop(self):
        logging.info("Service stop requested.")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self._kill_processes()

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        logging.info("Service starting.")
        self._run()

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    def _start_process(self, script: Path, label: str) -> subprocess.Popen | None:
        """Lance un subprocess Python et retourne le Popen."""
        env = os.environ.copy()
        # Transmettre les variables d'environnement importantes
        for key in ("VT_API_KEY", "API_SECRET", "ALERTEXPLAIN_API", "ALERTEXPLAIN_DEBUG"):
            val = os.getenv(key)
            if val:
                env[key] = val

        try:
            proc = subprocess.Popen(
                [PYTHON_EXE, str(script)],
                cwd=str(BASE_DIR),
                env=env,
                stdout=open(LOG_DIR / f"{label}.stdout.log", "a"),
                stderr=open(LOG_DIR / f"{label}.stderr.log", "a"),
            )
            logging.info(f"{label} started (PID={proc.pid})")
            return proc
        except Exception as e:
            logging.error(f"Failed to start {label}: {e}")
            return None

    def _kill_processes(self):
        for proc in self.processes:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    logging.info(f"Process PID={proc.pid} terminated.")
                except Exception as e:
                    logging.warning(f"Force-killing PID={proc.pid}: {e}")
                    try:
                        proc.kill()
                    except Exception:
                        pass
        self.processes.clear()

    def _run(self):
        # 1. Démarrer le serveur Flask (API + dashboard)
        proc_app = self._start_process(APP_PY, "app")
        if proc_app:
            self.processes.append(proc_app)
            time.sleep(2)   # laisser Flask démarrer avant le sniffer

        # 2. Démarrer le sniffer / IPS principal
        proc_main = self._start_process(MAIN_PY, "main")
        if proc_main:
            self.processes.append(proc_main)

        logging.info("Both processes running. Entering watch loop.")

        # 3. Boucle de surveillance — redémarre les process crashés
        while True:
            rc = win32event.WaitForSingleObject(self.stop_event, 5000)  # vérifie toutes les 5s
            if rc == win32event.WAIT_OBJECT_0:
                logging.info("Stop event received.")
                break

            # Auto-restart si un process est mort
            for i, (proc, script, label) in enumerate([
                (proc_app,  APP_PY,  "app"),
                (proc_main, MAIN_PY, "main"),
            ]):
                if proc and proc.poll() is not None:
                    logging.warning(f"{label} crashed (exit={proc.returncode}). Restarting...")
                    new_proc = self._start_process(script, label)
                    if new_proc:
                        self.processes[i] = new_proc
                        if label == "app":
                            proc_app  = new_proc
                        else:
                            proc_main = new_proc

        self._kill_processes()
        logging.info("Service stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Lancé par le SCM (Service Control Manager) Windows
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AlertExplainService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(AlertExplainService)
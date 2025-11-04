import sys
import os
from pathlib import Path
import subprocess
import logging
from shutil import which
from typing import Optional, List

# Get a logger for this module
logger = logging.getLogger(__name__)

# --- Use pathlib for all path definitions ---
USER_HOME = Path.home()
BASE_DIR = USER_HOME / ".PixieWeb"
SESSIONS_DIR = BASE_DIR / "sessions"
PIXIEWPS_DIR = BASE_DIR / "pixiewps"
REPORTS_DIR = Path.cwd() / "reports"
VULN_LIST_PATH = Path(__file__).parent.parent / "vulnwsc.txt"


# --- Centralized Subprocess Runner ---
def run_command(
    cmd: list[str], log_errors: bool = True
) -> Optional[subprocess.CompletedProcess]:
    """
    Runs an external command, logging errors uniformly.
    Returns the CompletedProcess object on success or failure.
    Returns None only on FileNotFoundError or OSError.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if result.returncode != 0 and log_errors:
            error_output = (result.stderr or result.stdout).strip()
            # Don't log "command failed" as scanner/wpas will handle it
            if (
                "command failed:" not in error_output
                and "wpa_supplicant" not in " ".join(cmd)
            ):
                logger.error(f'Command failed: {" ".join(cmd)}\n{error_output}')
        return result

    except FileNotFoundError:
        if log_errors:
            logger.error(f'Command not found: "{cmd[0]}"')
    except OSError as e:
        if log_errors:
            logger.error(f'OS error running command: {" ".join(cmd)}\n{e}')

    return None


def isAndroid() -> bool:
    """Check if running on Android (including Termux)."""
    # Check for Pydroid/Kivy style Android
    if hasattr(sys, "getandroidapilevel"):
        return True
    # Check for Termux environment
    if "TERMUX_VERSION" in os.environ:
        return True
    if os.environ.get("PREFIX") and "com.termux" in os.environ["PREFIX"]:
        return True
    return False


def checkRequirements(is_web: bool = False) -> None:
    """Checks if all required external commands are present."""
    if sys.version_info < (3, 9):
        die("The program requires Python 3.9 and above")

    if not is_web and os.getuid() != 0:
        die("Run it as root (or use --web if you already ran with sudo)")

    required_commands = ["pixiewps", "iw", "ip"]
    # Conditionally add rfkill only if not on Android
    if not isAndroid():
        required_commands.append("rfkill")
        
    missing_commands = []
    for cmd in required_commands:
        if not which(cmd):
            missing_commands.append(cmd)

    if missing_commands:
        die(
            "Missing required commands: "
            f'{", ".join(missing_commands)}'
            "\nPlease install them and ensure they are in your PATH."
        )
    logger.debug("All required commands found.")


def setupDirectories() -> None:
    """Creates or renames the application data directories."""
    old_dir = Path.home() / ".OSE"
    new_dir = BASE_DIR

    if old_dir.exists():
        try:
            old_dir.rename(new_dir)
            logger.info("Renamed legacy data directory")
        except OSError as e:
            logger.warning(f"Failed to rename data directory: {e}")

    for directory in [SESSIONS_DIR, PIXIEWPS_DIR, REPORTS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


def ifaceCtl(interface: str, action: str) -> int:
    """Brings an interface up or down. Returns 0 on success."""
    command = ["ip", "link", "set", interface, action]

    def _rfKillUnblock() -> bool:
        rfkill_command = ["rfkill", "unblock", "wifi"]
        result = run_command(rfkill_command)
        return bool(result and result.returncode == 0)

    result = run_command(command, log_errors=False)

    if result is None:
        logger.error('Failed to run "ip" command. Is it installed?')
        return 1
    if result.returncode == 0:
        return 0  # Success

    command_output_stripped = (result.stderr or result.stdout).strip()
    if command_output_stripped:
        logger.error(f"Failed to set interface {action}: \n{command_output_stripped}")

    if "RF-kill" in command_output_stripped and not isAndroid():
        logger.warning("RF-kill is blocking the interface, attempting to unblock...")
        if _rfKillUnblock():
            logger.info("Retrying command...")
            retry_result = run_command(command)
            if retry_result and retry_result.returncode == 0:
                return 0  # Success on retry
        else:
            logger.error("Failed to unblock RF-kill. Interface state unchanged.")

    return 1


def load_vuln_list() -> List[str]:
    """Loads the vulnerability list from vulnwsc.txt."""
    global VULN_LIST_PATH
    vuln_list: List[str] = []
    try:
        with open(VULN_LIST_PATH, "r", encoding="utf-8") as file:
            vuln_list = [line for line in (line.strip() for line in file) if line]
        logger.info(
            f"Loaded vulnerability list: {len(vuln_list)} entries from {VULN_LIST_PATH.name}"
        )
    except FileNotFoundError:
        logger.warning(
            f"Vulnerability list not found at {VULN_LIST_PATH}. Proceeding without it."
        )
    except (IOError, OSError) as e:
        logger.warning(f"Could not read vulnerability list: {e}")
    return vuln_list


def clearScreen() -> None:
    os.system("clear")


def die(text: str) -> None:
    logger.critical(text)
    sys.exit(text)

# --- NEW: Function to add to vulnerability list ---
def add_to_vuln_list(model_name: str) -> None:
    """Appends a new model name to the vulnerability list if it doesn't already exist."""
    global VULN_LIST, VULN_LIST_PATH
    
    if not model_name:
        logger.warning("Attack was successful, but no model name was found to add to list.")
        return

    try:
        # Normalize and check against the in-memory list
        # We load this list at startup in load_vuln_list
        if model_name.lower() in [m.lower() for m in VULN_LIST]:
            logger.info(f"Model '{model_name}' is already in the vulnerability list.")
            return
            
        # If not, append it to the file and the in-memory list
        with open(VULN_LIST_PATH, 'a', encoding='utf-8') as f:
            f.write(f"\n{model_name}")
        
        VULN_LIST.append(model_name) # Update in-memory list
        logger.info(f"Added '{model_name}' to {VULN_LIST_PATH.name}.")
        
    except Exception as e:
        logger.error(f"Failed to add model to vulnerability list: {e}")

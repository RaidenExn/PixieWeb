import uvicorn
import logging
import asyncio
import threading
import time
import os
import sys
import csv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager
from pydantic import BaseModel
from pathlib import Path

# Import your project's modules
import src.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args
from src.logger import setup_logging
import src.android

# --- Globals for Web UI ---
main_loop: Optional[asyncio.AbstractEventLoop] = None
main_thread_id: Optional[int] = None
VULN_LIST: List[str] = []
ATTACK_CANCEL_EVENT = threading.Event()
WEBSOCKET_MANAGER: Optional["ConnectionManager"] = None


# ==============================================================================
# === WEB UI (FastAPI) CODE ====================================================
# ==============================================================================

# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, data: dict):
        for connection in self.active_connections[:]:
            try:
                await connection.send_json(data)
            except Exception:
                self.disconnect(connection)


# --- Custom THREAD-SAFE Logging Handler ---
class WebSocketLogHandler(logging.Handler):
    def __init__(self, manager: ConnectionManager):
        super().__init__()
        self.manager = manager

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            log_data = {"type": "log", "level": record.levelname, "message": msg}
            coro = self.manager.broadcast_json(log_data)

            if main_loop and threading.current_thread().ident != main_thread_id:
                asyncio.run_coroutine_threadsafe(coro, main_loop)
            else:
                if main_loop and main_loop.is_running():
                    main_loop.create_task(coro)
        except Exception:
            pass  # Fail quietly


# --- FastAPI App Setup & Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop, main_thread_id, VULN_LIST, WEBSOCKET_MANAGER

    main_loop = asyncio.get_running_loop()
    main_thread_id = threading.current_thread().ident

    WEBSOCKET_MANAGER = ConnectionManager()  # Initialize manager

    # Configure logging for WEB mode
    setup_logging(verbose=False)
    root_logger = logging.getLogger()

    ws_handler = WebSocketLogHandler(WEBSOCKET_MANAGER)
    if root_logger.handlers:
        ws_handler.setFormatter(root_logger.handlers[0].formatter)

    root_logger.addHandler(ws_handler)
    root_logger.setLevel(logging.INFO)

    logging.info("Server starting up...")

    try:
        src.utils.checkRequirements(is_web=True)
        src.utils.setupDirectories()
        logging.info("Startup checks complete. Directories configured.")
        VULN_LIST = src.utils.load_vuln_list()
    except SystemExit as e:
        logging.critical(f"Startup check failed: {e}")
    except Exception as e:
        logging.critical(f"Startup check failed: {e}")

    yield

    logging.info("Server shutting down.")


app = FastAPI(lifespan=lifespan)


class AttackSettings(BaseModel):
    interface: str
    bssid: str
    essid: str
    attackType: str
    pin: Optional[str] = None
    delay: Optional[float] = None
    write: bool = True
    save: bool = True
    showPixieCmd: bool = False
    pixieForce: bool = False
    add_to_vuln_list: bool = False


@app.get("/", response_class=HTMLResponse)
async def get_root():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>Error: index.html not found</h1>", status_code=500)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not WEBSOCKET_MANAGER:
        return
    await WEBSOCKET_MANAGER.connect(websocket)
    logging.info("Web UI connected.")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        WEBSOCKET_MANAGER.disconnect(websocket)
        logging.info("Web UI disconnected.")


@app.post("/api/scan")
async def api_scan(interface: str, background_tasks: BackgroundTasks):
    if not interface:
        return {"error": "Interface is required"}
    logging.info(f"Scan requested for interface: {interface}")
    background_tasks.add_task(run_scan_task, interface)
    return {"message": "Scan started."}


@app.post("/api/attack")
async def api_attack(settings: AttackSettings, background_tasks: BackgroundTasks):
    logging.info(f"Attack requested: {settings.attackType} on {settings.bssid}")
    background_tasks.add_task(run_attack_task, settings)
    return {"message": f"Attack ({settings.attackType}) started."}


@app.post("/api/attack/stop")
async def api_stop_attack():
    logging.warning("Received request to stop attack.")
    ATTACK_CANCEL_EVENT.set()
    return {"message": "Stop signal sent."}


@app.get("/api/credentials", response_class=JSONResponse)
async def api_get_credentials():
    creds_file = src.utils.REPORTS_DIR / "stored.csv"
    credentials = []
    if not creds_file.is_file():
        return JSONResponse(content=credentials)
    try:
        with open(creds_file, "r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file, delimiter=";")
            
            # --- FIX for F841: Read and discard header ---
            next(reader)
            
            for row in reader:
                if row:
                    credentials.append(
                        {
                            "date": row[0],
                            "bssid": row[1],
                            "essid": row[2],
                            "pin": row[3],
                            "psk": row[4],
                        }
                    )
        return JSONResponse(content=credentials)
    except Exception as e:
        logging.error(f"Failed to read credentials file: {e}")
        return JSONResponse(
            content={"error": "Failed to read credentials file"}, status_code=500
        )


def run_scan_task(interface: str):
    global main_loop, VULN_LIST, WEBSOCKET_MANAGER
    try:
        if src.utils.ifaceCtl(interface, action="up") != 0:
            logging.error(f"Failed to bring up interface {interface}")
            return
        scanner = src.scanner.WiFiScanner(
            interface=interface, vuln_list=VULN_LIST, interactive=False
        )
        networks = scanner.scan_and_get_results()
        scan_data = {"type": "scan_results", "networks": networks}
        if main_loop and WEBSOCKET_MANAGER:
            asyncio.run_coroutine_threadsafe(
                WEBSOCKET_MANAGER.broadcast_json(scan_data), main_loop
            )
    except Exception as e:
        logging.error(f"An error occurred during scan: {e}")
    finally:
        if main_loop and WEBSOCKET_MANAGER:
            asyncio.run_coroutine_threadsafe(
                WEBSOCKET_MANAGER.broadcast_json({"type": "scan_complete"}), main_loop
            )


def run_attack_task(settings: AttackSettings):
    global main_loop, WEBSOCKET_MANAGER
    ATTACK_CANCEL_EVENT.clear()
    was_successful = False
    try:
        if src.utils.ifaceCtl(settings.interface, action="up") != 0:
            logging.error(f"Failed to bring up interface {settings.interface}")
            return
        start_time = time.monotonic()

        if settings.attackType == "bruteforce":
            connection = src.wps.bruteforce.Initialize(
                interface=settings.interface,
                loop_mode=False,
                write=settings.write,
                save=settings.save,
                cancel_event=ATTACK_CANCEL_EVENT,
            )
            connection.smartBruteforce(
                settings.bssid, settings.pin, settings.delay
            )
            if connection.CONNECTION.CONNECTION_STATUS.STATUS == "GOT_PSK":
                was_successful = True
        else:
            connection = src.wps.connection.Initialize(
                interface=settings.interface,
                write_result=settings.write,
                save_result=settings.save,
                cancel_event=ATTACK_CANCEL_EVENT,
            )
            was_successful = connection.singleConnection(
                bssid=settings.bssid,
                pin=settings.pin,
                pixiemode=(settings.attackType == "pixie"),
                showpixiecmd=settings.showPixieCmd,
                pixieforce=settings.pixieForce,
            )
        end_time = time.monotonic()
        if ATTACK_CANCEL_EVENT.is_set():
            logging.warning(f"Attack on {settings.bssid} was cancelled by user.")
        else:
            logging.info(
                f"{settings.attackType} attack on {settings.bssid} finished in {end_time - start_time:.2f} seconds."
            )

        if was_successful and settings.add_to_vuln_list and settings.model:
            src.utils.add_to_vuln_list(settings.model)

    except Exception as e:
        logging.error(f"An error occurred during attack: {e}")

    finally:
        if main_loop and WEBSOCKET_MANAGER:
            asyncio.run_coroutine_threadsafe(
                WEBSOCKET_MANAGER.broadcast_json(
                    {"type": "attack_complete", "success": was_successful}
                ),
                main_loop,
            )
        ATTACK_CANCEL_EVENT.clear()


def start_web_server():
    """Launches the FastAPI web server."""
    print("--- Starting PixieWeb UI ---")
    print("WARNING: This server must be run with sudo/root privileges.")
    # --- FIX: Changed to 127.0.0.1 ---
    print("Access the UI at http://127.0.0.1:8000")
    print("------------------------------------------")
    # --- FIX: Bind to 127.0.0.1 for security ---
    uvicorn.run("pixieweb:app", host="127.0.0.1", port=8000, reload=False)


# ==============================================================================
# === CLI (Original) CODE ======================================================
# ==============================================================================


def setupAndroidWifi(android_network: src.android.AndroidNetwork, enable: bool = False):
    if enable:
        android_network.enableWifi()
    else:
        android_network.storeAlwaysScanState()
        android_network.disableWifi()


def setupMediatekWifi(wmt_wifi_device: Path):
    if not wmt_wifi_device.is_char_device():
        src.utils.die(
            "Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): "
            f"{wmt_wifi_device} does not exist or it is not a character device"
        )
    try:
        wmt_wifi_device.chmod(0o644)
        wmt_wifi_device.write_text("1", encoding="utf-8")
    except (IOError, OSError) as e:
        src.utils.die(f"Failed to write to {wmt_wifi_device}: {e}")


def scanForNetworks(interface: str, vuln_list: list[str], reverse_scan: bool) -> str:
    scanner = src.scanner.WiFiScanner(
        interface, vuln_list, reverse_scan=reverse_scan, interactive=True
    )
    return scanner.promptNetwork()


def handleConnection_cli(args):
    """The original handleConnection function for CLI mode."""
    if args.bruteforce:
        connection = src.wps.bruteforce.Initialize(
            interface=args.interface,
            loop_mode=args.loop,
            write=args.write,
            save=args.save,
            cancel_event=threading.Event(),
        )
    else:
        connection = src.wps.connection.Initialize(
            interface=args.interface,
            write_result=args.write,
            save_result=args.save,
            cancel_event=threading.Event(),
        )

    if args.pbc:
        connection.singleConnection(pbc_mode=True)
    else:
        if not args.bssid:
            vuln_list = src.utils.load_vuln_list()  # Use new helper

            if not args.loop:
                logging.info(
                    "BSSID not specified (--bssid) — scanning for available networks"
                )

            args.bssid = scanForNetworks(args.interface, vuln_list, args.reverse_scan)

        if args.bssid:
            start_time = time.monotonic()
            if args.bruteforce:
                attack_type = "Bruteforce"
                connection.smartBruteforce(args.bssid, args.pin, args.delay)
            else:
                attack_type = "PIN/Pixie"
                connection.singleConnection(
                    args.bssid,
                    args.pin,
                    args.pixie_dust,
                    args.show_pixie_cmd,
                    args.pixie_force,
                )
            end_time = time.monotonic()
            logging.info(
                f"{attack_type} attack on {args.bssid} finished in {end_time - start_time:.2f} seconds."
            )


def start_cli(args):
    """The original main() function for CLI mode."""
    setup_logging(verbose=args.verbose)

    try:
        src.utils.checkRequirements(is_web=False)  # Pass is_web=False
        src.utils.setupDirectories()
    except SystemExit as e:
        sys.exit(str(e))

    wmt_wifi_device = Path("/dev/wmtWifi") if args.mtk_wifi else None
    android_network = None

    try:
        if src.utils.isAndroid() and not args.dts and not args.mtk_wifi:
            android_network = src.android.AndroidNetwork()
    except Exception as e:
        logging.error(f"Failed to initialize AndroidNetwork: {e}")

    while True:
        try:
            if args.clear:
                src.utils.clearScreen()
            if android_network:
                setupAndroidWifi(android_network)
            if args.mtk_wifi and wmt_wifi_device:
                setupMediatekWifi(wmt_wifi_device)
            if src.utils.ifaceCtl(args.interface, action="up"):
                src.utils.die(f"Unable to up interface '{args.interface}'")

            handleConnection_cli(args)

            if not args.loop:
                break
            args.bssid = None
        except KeyboardInterrupt:
            if args.loop:
                try:
                    if (
                        input(
                            "\n[?] Exit the script (otherwise continue to AP scan)? [N/y] "
                        ).lower()
                        == "y"
                    ):
                        logging.warning("Aborting…")
                        break
                    args.bssid = None
                except EOFError:
                    logging.warning("\nAborting…")
                    break
            else:
                logging.warning("\nAborting…")
                break
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            if not args.loop:
                break
            logging.info("Restarting loop...")
        finally:
            if android_network:
                try:
                    setupAndroidWifi(android_network, enable=True)
                except Exception as e:
                    logging.warning(f"Failed to restore Android Wi-Fi state: {e}")

    if args.iface_down:
        src.utils.ifaceCtl(args.interface, action="down")

    if args.mtk_wifi and wmt_wifi_device and wmt_wifi_device.exists():
        try:
            wmt_wifi_device.write_text("0", encoding="utf-8")
        except (IOError, OSError) as e:
            logging.error(f"Failed to write to {wmt_wifi_device} on exit: {e}")


# ==============================================================================
# === MAIN ENTRY POINT =========================================================
# ==============================================================================
if __name__ == "__main__":
    args = src.args.parseArgs()

    if args.web:
        # --- START WEB MODE ---
        if (
            args.interface
            or args.bssid
            or args.pin
            or args.bruteforce
            or args.pixie_dust
            or args.pbc
        ):
            print("[!] Error: Do not combine --web with other attack flags.")
            print("   The web UI uses its own settings.")
            sys.exit(1)

        start_web_server()

    else:
        # --- START CLI MODE ---
        if not args.interface:
            print("[!] Error: -i (interface) is required for CLI mode.")
            print("   Use --web to launch the Web UI.")
            sys.exit(1)

        start_cli(args)
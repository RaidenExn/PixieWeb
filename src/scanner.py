import re
import csv
import codecs
import logging
from typing import Dict, List, Tuple, Any, Optional

from rich.console import Console
from rich.table import Table

from src.utils import REPORTS_DIR
import src.utils

logger = logging.getLogger(__name__)

# REGEX constants
REGEX_BSS = re.compile(r"BSS (\S+)( )?\(on \w+\)")
REGEX_SSID = re.compile(r"SSID: (.*)")
REGEX_SIGNAL = re.compile(r"signal: ([+-]?([0-9]*[.])?[0-9]+) dBm")
REGEX_CAPABILITY = re.compile(r"(capability): (.+)")
REGEX_RSN = re.compile(r"(RSN):\t [*] Version: (\d+)")
REGEX_WPA = re.compile(r"(WPA):\t [*] Version: (\d+)")
REGEX_WPS_VER = re.compile(r"WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)")
REGEX_WPS_V2 = re.compile(r" [*] Version2: (.+)")
REGEX_WPS_AUTH = re.compile(r" [*] Authentication suites: (.+)")
REGEX_WPS_LOCK = re.compile(r" [*] AP setup locked: (0x[0-9]+)")
REGEX_MODEL = re.compile(r" [*] Model: (.*)")
REGEX_MODEL_NUM = re.compile(r" [*] Model Number: (.*)")
REGEX_DEV_NAME = re.compile(r" [*] Device name: (.*)")


class WiFiScanner:
    def __init__(
        self,
        interface: str,
        vuln_list: list[str] = None,
        reverse_scan: bool = False,
        interactive: bool = False,
    ):
        self.INTERFACE: str = interface
        self.VULN_LIST: list[str] = vuln_list if vuln_list else []
        self.REVERSE_SCAN: bool = reverse_scan
        self.INTERACTIVE: bool = interactive  # For CLI mode
        self.STORED: List[Tuple[str, str]] = []
        self.matchers = {
            REGEX_BSS: self._handleNetwork,
            REGEX_SSID: self._handleEssid,
            REGEX_SIGNAL: self._handleLevel,
            REGEX_CAPABILITY: self._handleSecurityType,
            REGEX_RSN: self._handleSecurityType,
            REGEX_WPA: self._handleSecurityType,
            REGEX_WPS_VER: self._handleWps,
            REGEX_WPS_V2: self._handleWpsVersion,
            REGEX_WPS_AUTH: self._handleSecurityType,
            REGEX_WPS_LOCK: self._handleWpsLocked,
            REGEX_MODEL: self._handleModel,
            REGEX_MODEL_NUM: self._handleModelNumber,
            REGEX_DEV_NAME: self._handleDeviceName,
        }

        reports_fname = REPORTS_DIR / "stored.csv"
        if not reports_fname.is_file():
            return
        try:
            with open(reports_fname, "r", newline="", encoding="utf-8") as file:
                csv_reader = csv.reader(file, delimiter=";", quoting=csv.QUOTE_ALL)
                next(csv_reader)  # Skip header
                for row in csv_reader:
                    if len(row) >= 3:
                        self.STORED.append((row[1], row[2]))
        except Exception:
            logger.error(
                f"Error reading {reports_fname}, stored networks list may be incomplete."
            )

    def scan_and_get_results(self) -> List[Dict[str, Any]]:
        """(FOR WEB UI) Runs a scan, enriches data, and returns the network list."""
        logger.info("Scanning for networks...")
        networks_dict = self._iwScanner()
        if not networks_dict:
            logger.warning("No WPS networks found.")
            return []

        networks_list = []
        for net in networks_dict.values():
            model = f'{net["Model"]} {net["Model_number"]}'.strip()
            device_name = net["Device name"]
            net["status"] = self._get_network_status(net, model, device_name)
            networks_list.append(net)

        logger.info(f"Scan complete. Found {len(networks_list)} WPS networks.")
        return networks_list

    def promptNetwork(self) -> str:
        """(FOR CLI) Scans, prints table, and asks user for input."""
        if not self.INTERACTIVE:
            logger.critical("promptNetwork() called in non-interactive mode.")
            return ""

        networks = self._iwScanner()
        if not networks:
            logger.warning("No WPS networks found.")
            return ""

        while True:
            try:
                network_no_str = input("Select target (press Enter to refresh): ")
                if network_no_str.lower() in {"r", "0", ""}:
                    src.utils.clearScreen()
                    return self.promptNetwork()
                network_no = int(network_no_str)
                if network_no in networks:
                    return networks[network_no]["BSSID"]
                print("Invalid number")  # This print is fine for CLI
            except (ValueError, IndexError):
                print("Invalid number")
            except EOFError:
                print("\nAborting...")
                return ""

    def _get_network_status(
        self, network: Dict[str, Any], model: str, device_name: str
    ) -> str:
        """Determines the vulnerability status of a network."""
        if (network["BSSID"], network["ESSID"]) in self.STORED:
            return "already_stored"
        if (model in self.VULN_LIST) or (device_name in self.VULN_LIST):
            if model or device_name:
                return "vulnerable_model"
        if network["WPS_locked"]:
            return "wps_locked"
        if network["WPS_version"] == "1.0":
            return "vulnerable_version"
        return "default"

    @staticmethod
    def _decode_iw_string(s: str) -> str:
        try:
            return (
                codecs.decode(s, "unicode-escape")
                .encode("latin1")
                .decode("utf-8", errors="replace")
            )
        except (UnicodeDecodeError, UnicodeEncodeError):
            return s

    def _handleNetwork(self, result: re.Match, networks: List[Dict]) -> None:
        networks.append(
            {
                "ESSID": "",
                "Security type": "Unknown",
                "WPS": False,
                "WPS_version": "1.0",
                "WPS_locked": False,
                "Model": "",
                "Model_number": "",
                "Device name": "",
                "BSSID": result.group(1).upper(),
            }
        )

    def _handleEssid(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]["ESSID"] = self._decode_iw_string(result.group(1))

    def _handleLevel(self, result: re.Match, networks: List[Dict]) -> None:
        try:
            networks[-1]["Level"] = int(float(result.group(1)))
        except (ValueError, IndexError):
            networks[-1]["Level"] = -100

    def _handleSecurityType(self, result: re.Match, networks: List[Dict]) -> None:
        sec = networks[-1]["Security type"]
        if result.group(1) == "capability":
            if "Privacy" in result.group(2):
                sec = "WEP"
            else:
                sec = "Open"
        elif sec == "WEP":
            if result.group(1) == "RSN":
                sec = "WPA2"
            elif result.group(1) == "WPA":
                sec = "WPA"
        elif sec == "WPA":
            if result.group(1) == "RSN":
                sec = "WPA/WPA2"
        elif sec == "WPA2":
            if result.group(1) == "PSK SAE":
                sec = "WPA2/WPA3"
            elif result.group(1) == "WPA":
                sec = "WPA/WPA2"
        networks[-1]["Security type"] = sec

    def _handleWps(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]["WPS"] = bool(result.group(1))

    def _handleWpsVersion(self, result: re.Match, networks: List[Dict]) -> None:
        wps_ver_filtered = result.group(1).replace("* Version2:", "")
        if wps_ver_filtered == "2.0":
            networks[-1]["WPS_version"] = "2.0"

    def _handleWpsLocked(self, result: re.Match, networks: List[Dict]) -> None:
        try:
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]["WPS_locked"] = True
        except (ValueError, IndexError):
            pass

    def _handleModel(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]["Model"] = self._decode_iw_string(result.group(1))

    def _handleModelNumber(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]["Model_number"] = self._decode_iw_string(result.group(1))

    def _handleDeviceName(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]["Device name"] = self._decode_iw_string(result.group(1))

    def _printNetworkTable(self, network_list_items: List[Tuple[int, Dict]]) -> None:
        """Prints the network table to the console/log."""
        console = Console()
        console.print(
            "Network marks: [bold green]Vulnerable model[/] | "
            "[green]Vulnerable WPS ver.[/] | "
            "[bold red]WPS locked[/] | "
            "[bold yellow]Already stored[/]"
        )

        table = Table()
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("BSSID", style="magenta", no_wrap=True)
        table.add_column("ESSID")
        table.add_column("Sec.")
        table.add_column("PWR", justify="right")
        table.add_column("Ver.")
        table.add_column("WSC name")
        table.add_column("WSC model")

        if self.REVERSE_SCAN:
            network_list_items = network_list_items[::-1]

        for n, network in network_list_items:
            model = f'{network["Model"]} {network["Model_number"]}'.strip()
            device_name = network["Device name"]
            essid = network["ESSID"]
            if len(essid) > 25:
                essid = essid[:25] + "…"
            if len(device_name) > 27:
                device_name = device_name[:27] + "…"

            status = self._get_network_status(network, model, device_name)
            style_map = {
                "already_stored": "bold yellow",
                "vulnerable_model": "bold green",
                "wps_locked": "bold red",
                "vulnerable_version": "green",
                "default": None,
            }
            style = style_map.get(status)

            table.add_row(
                f"{n})",
                network["BSSID"],
                essid,
                network["Security type"],
                str(network["Level"]),
                network["WPS_version"],
                device_name,
                model,
                style=style,
            )

        console.print(table)

    def _iwScanner(self) -> Optional[Dict[int, Dict[str, Any]]]:
        """Internal scan function. Returns a dict of networks or None."""
        networks: List[Dict] = []
        command = ["iw", "dev", f"{self.INTERFACE}", "scan"]

        iw_scan_process = src.utils.run_command(command, log_errors=False)

        if iw_scan_process is None:
            logger.error('Failed to run "iw" command. Is it installed?')
            return None

        if iw_scan_process.returncode != 0:
            error_output = (iw_scan_process.stderr or iw_scan_process.stdout).strip()
            logger.error(f"Failed to perform an iw scan: \n {error_output}")
            return None

        lines = iw_scan_process.stdout.splitlines()
        for line in lines:
            if line.startswith("command failed:"):
                logger.error(f"Error: {line}")
                return None

            line = line.strip("\t")
            for regexp, handler in self.matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(res, networks)
                    break

        networks = list(filter(lambda x: bool(x.get("WPS")), networks))
        if not networks:
            return None

        networks.sort(key=lambda x: x.get("Level", -100), reverse=True)
        network_list = {(i + 1): network for i, network in enumerate(networks)}

        # Only print the table if in interactive (CLI) mode
        if self.INTERACTIVE:
            network_list_items = list(network_list.items())
            self._printNetworkTable(network_list_items)

        return network_list

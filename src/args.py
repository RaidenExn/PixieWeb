import argparse
import os


def parseArgs():
    parser = argparse.ArgumentParser(
        description="PixieWeb",
        epilog="Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K",
    )

    # --- Group for CLI vs WEB ---
    mode_group = parser.add_mutually_exclusive_group()

    mode_group.add_argument(
        "-i",
        "--interface",
        type=str,
        required=False,  # <-- No longer required, will be validated by main script
        help="Name of the interface to use (required for CLI mode)",
    )

    mode_group.add_argument(
        "-web",
        action="store_true",
        help="Launch the web interface instead of the command-line tool",
    )

    # --- CLI Only Arguments ---
    cli_group = parser.add_argument_group("CLI Arguments")

    cli_group.add_argument("-b", "--bssid", type=str, help="BSSID of the target AP")
    cli_group.add_argument(
        "-p",
        "--pin",
        type=str,
        help="Use the specified pin (arbitrary string or 4/8 digit pin). Enter a blank pin (e.g. '') for a Null Pin attack",
    )
    cli_group.add_argument(
        "-K", "--pixie-dust", action="store_true", help="Run Pixie Dust attack"
    )
    cli_group.add_argument(
        "-F",
        "--pixie-force",
        action="store_true",
        help="Run Pixiewps with --force option (bruteforce full range)",
    )
    cli_group.add_argument(
        "-X",
        "--show-pixie-cmd",
        action="store_true",
        help="Always print Pixiewps command",
    )
    cli_group.add_argument(
        "-B", "--bruteforce", action="store_true", help="Run online bruteforce attack"
    )
    cli_group.add_argument(
        "--pbc",
        "--push-button-connect",
        action="store_true",
        help="Run WPS push button connection",
    )
    cli_group.add_argument(
        "-d", "--delay", type=float, help="Set the delay between pin attempts"
    )
    cli_group.add_argument(
        "-w",
        "--write",
        action="store_true",
        help="Write credentials to the file on success",
    )
    cli_group.add_argument(
        "-s",
        "--save",
        action="store_true",
        help="Save the AP to network manager on success",
    )
    cli_group.add_argument(
        "--iface-down",
        action="store_true",
        help="Down network interface when the work is finished",
    )
    cli_group.add_argument(
        "--vuln-list",
        type=str,
        default=os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "vulnwsc.txt")
        ),
        help="Use custom file with vulnerable devices list",
    )
    cli_group.add_argument("-l", "--loop", action="store_true", help="Run in a loop")
    cli_group.add_argument(
        "-c",
        "--clear",
        action="store_true",
        help="Clear the screen on every wi-fi scan",
    )
    cli_group.add_argument(
        "-r",
        "--reverse-scan",
        action="store_true",
        help="Reverse order of networks in the list of networks. Useful on small displays",
    )
    cli_group.add_argument(
        "--mtk-wifi",
        action="store_true",
        help="Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit "
        "(for internal Wi-Fi adapters implemented in MediaTek SoCs). "
        "Turn off Wi-Fi in the system settings before using this.",
    )
    cli_group.add_argument(
        "--dts",
        "--dont-touch-settings",
        action="store_true",
        help="Don't touch the Android Wi-Fi settings on startup and exit. "
        "Use when having device-specific issues",
    )
    cli_group.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    return parser.parse_args()

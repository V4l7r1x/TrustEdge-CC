#!/usr/bin/env python3
"""
TrustEdge-CC: Pico 2 USB CDC Serial Bridge
Relays telemetry and model updates between physical Raspberry Pi Pico 2 (via USB Serial)
and the Central Orchestrator REST/WebSocket API.
"""

import os
import sys
import glob
import time
import json
import logging
import argparse
import requests
import serial

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [PICO-BRIDGE:%(levelname)s] %(message)s")
logger = logging.getLogger("PicoBridge")


def find_pico_ports():
    """Detect available USB CDC serial devices"""
    ports = glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*")
    return ports


def run_bridge(port: str, baud: int, server_url: str):
    logger.info("Opening serial port %s at %d baud...", port, baud)
    server_url = server_url.rstrip("/")

    try:
        ser = serial.Serial(port, baud, timeout=1.0)
    except Exception as e:
        logger.error("Failed to open serial port %s: %s", port, str(e))
        return

    logger.info("Serial bridge active. Listening for packets from Pico 2...")
    while True:
        try:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # Check if line is valid JSON packet from Pico 2
            if line.startswith("{") and line.endswith("}"):
                data = json.loads(line)
                pkt_type = data.get("type", "telemetry")

                if pkt_type == "register":
                    resp = requests.post(f"{server_url}/api/nodes/register", json=data.get("payload", {}))
                    logger.info("Pico registration relayed: HTTP %d", resp.status_code)

                elif pkt_type == "telemetry":
                    resp = requests.post(f"{server_url}/api/telemetry/report", json=data.get("payload", {}))
                    logger.info("Pico telemetry relayed: %s", data.get("payload", {}))

                elif pkt_type == "fl_update":
                    resp = requests.post(f"{server_url}/api/fl/submit-update", json=data.get("payload", {}))
                    logger.info("Pico FL update relayed: HTTP %d", resp.status_code)

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error("Bridge exception: %s", str(e))
            time.sleep(0.5)

    ser.close()


def main():
    parser = argparse.ArgumentParser(description="TrustEdge-CC Pico 2 USB Serial Bridge")
    parser.add_argument("--port", type=str, default="", help="Serial port (e.g. /dev/ttyACM0). Auto-detects if omitted.")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default 115200)")
    parser.add_argument("--server", type=str, default="http://localhost:8000", help="Orchestrator URL")
    args = parser.parse_args()

    port = args.port
    if not port:
        available = find_pico_ports()
        if not available:
            logger.error("No Pico serial devices found on /dev/ttyACM* or /dev/ttyUSB*.")
            logger.info("Note: You can run 'python3 pico_nodes/pico_simulator.py' to simulate Pico 1 & 2 before connecting physical boards.")
            sys.exit(1)
        port = available[0]
        logger.info("Auto-detected Pico 2 on %s", port)

    run_bridge(port, args.baud, args.server)


if __name__ == "__main__":
    main()

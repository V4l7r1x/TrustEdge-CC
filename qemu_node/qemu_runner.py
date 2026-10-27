#!/usr/bin/env python3
"""
TrustEdge-CC: QEMU ARM TrustZone-A OP-TEE Node Runner
Emulates or interfaces with the ARM Cortex-A Secure World (OP-TEE TA).
Generates telemetry, executes in-TEE Isolation Forest training, produces ECDSA
integrity signatures, AES-GCM encryption, and communicates with the Orchestrator.
"""

import os
import sys
import time
import json
import random
import logging
import argparse
import requests
from typing import Dict, Any, List

# Ensure parent directory is in Python path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.crypto_utils import EdgeCryptoEngine
from common.isolation_forest import EdgeIsolationForest

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [OP-TEE-NODE:%(levelname)s] %(message)s"
)
logger = logging.getLogger("QemuOpteeNode")


class QemuOpteeNode:
    def __init__(self,
                 node_id: str = "qemu-arm-node-01",
                 server_url: str = "http://localhost:8000",
                 sample_interval: float = 2.0):
        self.node_id = node_id
        self.server_url = server_url.rstrip("/")
        self.sample_interval = sample_interval

        # OP-TEE Secure World hardware configuration
        self.tee_type = "OP-TEE_TrustZone-A"
        self.ta_uuid = "c4a52140-59f2-43bb-8e31-893080bf0001"
        self.enclave_measurement = "e83b4fa91c7816bc83017a42fe93c52e8913b8214f77c381a1795bc9e295da90"

        # Initialize Hardware-Sealed Root Key inside Secure World
        logger.info("Initializing ARM TrustZone-A Root Key & OP-TEE TA context...")
        self.crypto = EdgeCryptoEngine()
        self.aes_session_key = os.urandom(32)  # 256-bit AES key

        # Isolation Forest detector inside Secure RAM
        self.local_model = EdgeIsolationForest(n_estimators=10, max_samples=32)
        self.sensor_buffer: List[List[float]] = []
        self.buffer_capacity = 64

        # Initial bootstrap training with baseline data
        self._bootstrap_training()

        self.registered = False
        self.last_round_participated = -1
        self.running = False
        self.anomaly_forced = False

    def _bootstrap_training(self):
        """Pre-populate buffer with normal ambient readings (temperature ~ 24°C, humidity ~ 45%)"""
        baseline_data = []
        for _ in range(40):
            temp = round(random.gauss(24.5, 0.8), 2)
            hum = round(random.gauss(45.0, 1.5), 2)
            baseline_data.append([temp, hum])
            self.sensor_buffer.append([temp, hum])
        self.local_model.fit(baseline_data)
        logger.info("OP-TEE TA bootstrapped with %d normal baseline samples", len(baseline_data))

    def register_node(self) -> bool:
        """Register node with Central Orchestrator using TEE-signed Attestation Evidence"""
        evidence = self.crypto.generate_attestation_evidence(
            node_id=self.node_id,
            tee_type=self.tee_type,
            enclave_measurement=self.enclave_measurement
        )

        reg_payload = {
            "node_id": self.node_id,
            "node_type": "QEMU_ARM_CortexA",
            "tee_type": self.tee_type,
            "ta_uuid": self.ta_uuid,
            "public_key": self.crypto.export_public_key_pem(),
            "attestation": evidence,
            "aes_key_hex": self.aes_session_key.hex()
        }

        url = f"{self.server_url}/api/nodes/register"
        try:
            resp = requests.post(url, json=reg_payload, timeout=5)
            if resp.status_code == 200:
                logger.info("Successfully registered with Orchestrator (Zero-Trust Verified)")
                self.registered = True
                return True
            else:
                logger.error("Failed to register node: HTTP %d: %s", resp.status_code, resp.text)
                return False
        except Exception as e:
            logger.error("Connection failed during registration: %s", str(e))
            return False

    def read_sensor_data(self) -> List[float]:
        """
        Simulate sensor reading acquisition (Temp & Humidity).
        Supports simulated anomaly injection when triggered.
        """
        if self.anomaly_forced:
            # Inject extreme anomaly (e.g. fire/sensor fault: 85°C, 92% humidity)
            temp = round(random.uniform(75.0, 95.0), 2)
            hum = round(random.uniform(85.0, 99.0), 2)
        else:
            # Normal industrial ambient variation
            temp = round(random.gauss(24.8, 1.1), 2)
            hum = round(random.gauss(46.0, 2.0), 2)

        return [temp, hum]

    def process_telemetry_tick(self):
        """Execute in-enclave anomaly inference on current telemetry and transmit to Orchestrator"""
        reading = self.read_sensor_data()
        self.sensor_buffer.append(reading)
        if len(self.sensor_buffer) > self.buffer_capacity:
            self.sensor_buffer.pop(0)

        t_start = time.perf_counter()
        label, score = self.local_model.predict(reading)
        t_infer_ms = (time.perf_counter() - t_start) * 1000.0

        telemetry_payload = {
            "node_id": self.node_id,
            "timestamp": time.time(),
            "temperature": reading[0],
            "humidity": reading[1],
            "anomaly_score": round(score, 4),
            "is_anomaly": (label == -1),
            "tee_latency_ms": round(t_infer_ms, 3),
            "anomaly_forced": self.anomaly_forced
        }

        url = f"{self.server_url}/api/telemetry/report"
        try:
            requests.post(url, json=telemetry_payload, timeout=2)
            status_tag = "ANOMALY DETECTED!" if label == -1 else "NORMAL"
            logger.info("Telemetry [%s] Temp: %.1f C, Hum: %.1f%% | Anomaly Score: %.3f (TEE: %.2f ms)",
                        status_tag, reading[0], reading[1], score, t_infer_ms)
        except Exception as e:
            logger.debug("Failed sending telemetry: %s", str(e))

    def check_and_execute_fl_round(self):
        """Check if an active FL round is waiting for this node's update"""
        url = f"{self.server_url}/api/fl/status"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code != 200:
                return

            fl_state = resp.json()
            current_round = fl_state.get("current_round", 0)
            round_active = fl_state.get("is_active", False)

            if round_active and current_round > self.last_round_participated:
                logger.info(">>> Active Federated Learning Round #%d detected! Starting in-TEE training...", current_round)
                self.train_and_submit_update(current_round)
        except Exception as e:
            logger.debug("FL status check exception: %s", str(e))

    def train_and_submit_update(self, fl_round: int):
        """
        Train local Isolation Forest inside OP-TEE Secure World,
        compute digest, sign with hardware-sealed ECDSA key, encrypt with AES-GCM,
        and submit to orchestrator.
        """
        if len(self.sensor_buffer) < 10:
            logger.warning("Not enough samples in TEE buffer for FL training")
            return

        t_start = time.perf_counter()

        # In-TEE local training
        self.local_model.fit(self.sensor_buffer)
        t_train_ms = (time.perf_counter() - t_start) * 1000.0

        model_dict = self.local_model.to_dict()
        model_json_bytes = json.dumps(model_dict, sort_keys=True).encode("utf-8")

        # 1. Compute SHA-256 digest of local model update
        model_digest = self.crypto.hash_sha256(model_json_bytes)

        # 2. Hardware-sealed ECDSA signature over the update digest
        signature_bytes = self.crypto.sign_data(model_digest.encode("utf-8"))
        signature_b64 = __import__("base64").b64encode(signature_bytes).decode("utf-8")

        # 3. AES-256-GCM encryption of model weights for privacy-preserving transit
        encrypted_obj = self.crypto.encrypt_aes_gcm(
            aes_key=self.aes_session_key,
            plaintext=model_json_bytes,
            aad=f"round-{fl_round}:{self.node_id}".encode("utf-8")
        )

        memory_bytes = self.local_model.memory_footprint_bytes()

        submission_payload = {
            "node_id": self.node_id,
            "round": fl_round,
            "model_digest": model_digest,
            "signature": signature_b64,
            "encrypted_model": encrypted_obj,
            "aad": f"round-{fl_round}:{self.node_id}",
            "execution_stats": {
                "tee_type": self.tee_type,
                "training_latency_ms": round(t_train_ms, 2),
                "memory_footprint_bytes": memory_bytes,
                "n_trees_contributed": len(self.local_model.trees)
            }
        }

        url = f"{self.server_url}/api/fl/submit-update"
        try:
            resp = requests.post(url, json=submission_payload, timeout=6)
            if resp.status_code == 200:
                logger.info("Local model update for Round #%d successfully verified and accepted by Aggregator!", fl_round)
                self.last_round_participated = fl_round
                # Fetch updated global model
                self.fetch_global_model()
            else:
                logger.error("Update rejected by Orchestrator: %s", resp.text)
        except Exception as e:
            logger.error("Failed submitting FL update: %s", str(e))

    def fetch_global_model(self):
        """Download latest aggregated global model and update local detector"""
        url = f"{self.server_url}/api/fl/global-model"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data and "trees" in data and len(data["trees"]) > 0:
                    self.local_model = EdgeIsolationForest.from_dict(data)
                    logger.info("Local detector updated with Global Model (%d aggregated trees)", len(self.local_model.trees))
        except Exception as e:
            logger.debug("Failed fetching global model: %s", str(e))

    def start(self):
        """Main operational loop"""
        self.running = True
        logger.info("=== Starting TrustEdge-CC QEMU OP-TEE Node [%s] ===", self.node_id)

        # Retry registration until connected
        while self.running and not self.registered:
            logger.info("Connecting to Orchestrator at %s...", self.server_url)
            if self.register_node():
                break
            time.sleep(3)

        # Main cycle
        fl_check_counter = 0
        while self.running:
            try:
                self.process_telemetry_tick()
                fl_check_counter += 1
                if fl_check_counter >= 3:
                    self.check_and_execute_fl_round()
                    fl_check_counter = 0
                time.sleep(self.sample_interval)
            except KeyboardInterrupt:
                logger.info("Stopping QEMU node...")
                break
            except Exception as e:
                logger.error("Error in node loop: %s", str(e))
                time.sleep(self.sample_interval)


def main():
    parser = argparse.ArgumentParser(description="TrustEdge-CC QEMU ARM TrustZone-A Node")
    parser.add_argument("--server", type=str, default="http://localhost:8000", help="Orchestrator URL")
    parser.add_argument("--node-id", type=str, default="qemu-arm-cortex-a", help="Edge node ID")
    parser.add_argument("--interval", type=float, default=2.0, help="Telemetry sample interval (seconds)")
    args = parser.parse_args()

    node = QemuOpteeNode(node_id=args.node_id, server_url=args.server, sample_interval=args.interval)
    node.start()


if __name__ == "__main__":
    main()

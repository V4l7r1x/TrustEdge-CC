#!/usr/bin/env python3
"""
TrustEdge-CC: Raspberry Pi Pico 2 (RP2350 ARM TrustZone-M / TF-M) Node Simulator
Emulates the physical Pico 2 board running TF-M Secure Partition, DHT11 sensor readings,
in-enclave Isolation Forest training, ECDSA signatures, and AES-GCM encryption.
"""

import os
import sys
import time
import json
import random
import logging
import argparse
import requests
from typing import List

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.crypto_utils import EdgeCryptoEngine
from common.isolation_forest import EdgeIsolationForest

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [PICO2-TFM:%(levelname)s] %(message)s")
logger = logging.getLogger("PicoTfmNode")


class Pico2Node:
    def __init__(self,
                 node_id: str = "pico2-m33-node-01",
                 server_url: str = "http://localhost:8000",
                 sample_interval: float = 2.5):
        self.node_id = node_id
        self.server_url = server_url.rstrip("/")
        self.sample_interval = sample_interval

        # Hardware TrustZone-M (TF-M) details for RP2350
        self.tee_type = "TF-M_TrustZone-M_RP2350"
        self.enclave_measurement = "a3f590bc128e4d3a81765c0299f012eb443a7891bcdef0123456789abcdef012"

        # Hardware-sealed key emulation
        self.crypto = EdgeCryptoEngine()
        self.aes_session_key = os.urandom(32)

        # In-enclave Isolation forest (<160KB RAM footprint on Cortex-M33)
        self.local_model = EdgeIsolationForest(n_estimators=8, max_samples=24)
        self.sensor_buffer: List[List[float]] = []
        self.buffer_capacity = 40
        self._bootstrap_buffer()

        self.registered = False
        self.last_round_participated = -1
        self.running = False
        self.anomaly_forced = False

    def _bootstrap_buffer(self):
        for _ in range(30):
            temp = round(random.gauss(23.8, 0.9), 2)
            hum = round(random.gauss(48.2, 1.8), 2)
            self.sensor_buffer.append([temp, hum])
        self.local_model.fit(self.sensor_buffer)

    def register(self) -> bool:
        evidence = self.crypto.generate_attestation_evidence(
            node_id=self.node_id,
            tee_type=self.tee_type,
            enclave_measurement=self.enclave_measurement
        )
        payload = {
            "node_id": self.node_id,
            "node_type": "RP2350_Cortex_M33",
            "tee_type": self.tee_type,
            "public_key": self.crypto.export_public_key_pem(),
            "attestation": evidence,
            "aes_key_hex": self.aes_session_key.hex()
        }
        try:
            resp = requests.post(f"{self.server_url}/api/nodes/register", json=payload, timeout=5)
            if resp.status_code == 200:
                logger.info("Pico 2 Node [%s] verified via TF-M PSA Cryptography", self.node_id)
                self.registered = True
                return True
            else:
                logger.error("Registration failed: %s", resp.text)
                return False
        except Exception as e:
            logger.error("Registration exception: %s", str(e))
            return False

    def read_dht11(self) -> List[float]:
        if self.anomaly_forced:
            temp = round(random.uniform(70.0, 90.0), 2)
            hum = round(random.uniform(80.0, 98.0), 2)
        else:
            temp = round(random.gauss(24.0, 1.0), 2)
            hum = round(random.gauss(47.5, 2.2), 2)
        return [temp, hum]

    def process_telemetry(self):
        reading = self.read_dht11()
        self.sensor_buffer.append(reading)
        if len(self.sensor_buffer) > self.buffer_capacity:
            self.sensor_buffer.pop(0)

        t_start = time.perf_counter()
        label, score = self.local_model.predict(reading)
        t_infer_ms = (time.perf_counter() - t_start) * 1000.0

        payload = {
            "node_id": self.node_id,
            "timestamp": time.time(),
            "temperature": reading[0],
            "humidity": reading[1],
            "anomaly_score": round(score, 4),
            "is_anomaly": (label == -1),
            "tee_latency_ms": round(t_infer_ms, 3),
            "anomaly_forced": self.anomaly_forced
        }
        try:
            requests.post(f"{self.server_url}/api/telemetry/report", json=payload, timeout=2)
        except Exception:
            pass

    def check_fl_round(self):
        try:
            resp = requests.get(f"{self.server_url}/api/fl/status", timeout=2)
            if resp.status_code == 200:
                state = resp.json()
                curr_round = state.get("current_round", 0)
                if state.get("is_active", False) and curr_round > self.last_round_participated:
                    logger.info("Executing TF-M in-enclave training for Round #%d...", curr_round)
                    self.submit_update(curr_round)
        except Exception:
            pass

    def submit_update(self, fl_round: int):
        t_start = time.perf_counter()
        self.local_model.fit(self.sensor_buffer)
        t_train_ms = (time.perf_counter() - t_start) * 1000.0

        model_dict = self.local_model.to_dict()
        model_bytes = json.dumps(model_dict, sort_keys=True).encode("utf-8")

        digest = self.crypto.hash_sha256(model_bytes)
        sig = self.crypto.sign_data(digest.encode("utf-8"))
        sig_b64 = __import__("base64").b64encode(sig).decode("utf-8")

        encrypted_obj = self.crypto.encrypt_aes_gcm(
            aes_key=self.aes_session_key,
            plaintext=model_bytes,
            aad=f"round-{fl_round}:{self.node_id}".encode("utf-8")
        )

        payload = {
            "node_id": self.node_id,
            "round": fl_round,
            "model_digest": digest,
            "signature": sig_b64,
            "encrypted_model": encrypted_obj,
            "aad": f"round-{fl_round}:{self.node_id}",
            "execution_stats": {
                "tee_type": self.tee_type,
                "training_latency_ms": round(t_train_ms, 2),
                "memory_footprint_bytes": self.local_model.memory_footprint_bytes(),
                "n_trees_contributed": len(self.local_model.trees)
            }
        }
        try:
            resp = requests.post(f"{self.server_url}/api/fl/submit-update", json=payload, timeout=5)
            if resp.status_code == 200:
                self.last_round_participated = fl_round
                logger.info("Pico 2 [%s] update successfully accepted for Round #%d!", self.node_id, fl_round)
        except Exception as e:
            logger.error("Failed submitting update: %s", str(e))

    def start(self):
        self.running = True
        logger.info("Starting Pico 2 Node [%s]...", self.node_id)
        while self.running and not self.registered:
            if self.register():
                break
            time.sleep(3)

        fl_ticks = 0
        while self.running:
            try:
                self.process_telemetry()
                fl_ticks += 1
                if fl_ticks >= 3:
                    self.check_fl_round()
                    fl_ticks = 0
                time.sleep(self.sample_interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                time.sleep(self.sample_interval)


def main():
    parser = argparse.ArgumentParser(description="TrustEdge-CC Pico 2 Node")
    parser.add_argument("--server", type=str, default="http://localhost:8000")
    parser.add_argument("--node-id", type=str, default="pico2-device-1")
    parser.add_argument("--interval", type=float, default=2.5)
    args = parser.parse_args()

    node = Pico2Node(node_id=args.node_id, server_url=args.server, sample_interval=args.interval)
    node.start()


if __name__ == "__main__":
    main()

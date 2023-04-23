import argparse
import logging
import sys
import time
from hashlib import sha256
import hmac
from typing import List
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes


POOL_URL = "http://etc.hiveon.com"
POOL_PORT = 4444


class HiveonMiner:
    def __init__(self):
        """
        Class constructor for HiveonMiner.
        """
        self._logger = logging.getLogger("hiveon-miner")
        self._pool_url = POOL_URL
        self._pool_port = POOL_PORT
        self._wallet_address = input("Enter your wallet address: ")
        self._worker_name = input("Enter your worker name: ")
        self._job = None
        self._job_id = None
        self._nonce = None
        self._hash_result = ""


    def subscribe(self, session):
        """
        Subscribes to the Hiveon mining pool.
        Parameters:
        - session: The session to use for the request.
        """
        self._logger.info("Subscribing to Hiveon pool")
        subscribe_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "mining.subscribe",
            "params": ["Miner", "Hiveon-CustomMiner/1.0.0"],
        }
        response = session.post(f"{self._pool_url}:{self._pool_port}/", json=subscribe_request)
        if response.status_code != 200:
            raise Exception(f"Failed to subscribe: {response.text}")
        result = response.json()["result"]
        session.headers["Authorization"] = f"{result[1]}"
        self._logger.info("Authorized")
        return result

    def get_job(self, session):
        self._logger.debug("Getting job")
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "mining.getJob",
            "params": [self._wallet_address, self._worker_name],
        }
        response = session.post(f"{self._pool_url}:{self._pool_port}/", json=request)
        if response.status_code != 200:
            raise Exception(f"Failed to get job: {response.text}")
        result = response.json()["result"]
        self._logger.debug(f"Got job: {result}")
        return result

    def submit_hash(self, session):
        self._logger.debug("Submitting hash")
        request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "mining.submit",
            "params": [self._wallet_address, self._job_id, self._nonce, self._hash_result],
        }
        response = session.post(f"{self._pool_url}:{self._pool_port}/", json=request)
        if response.status_code != 200:
            raise Exception(f"Failed to submit hash: {response.text}")
        result = response.json()["result"]
        self._logger.debug(f"Hash submitted: {result}")
        return result

    def _encrypt(self, key, data):
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(data, 16))
        return iv + ciphertext


    def _get_encrypted_share(self, session, share):
        self._logger.debug(f"Encrypting share: {share}")

        key = bytes.fromhex(self._get_key(session))

        share_bytes = bytearray(share.encode("utf-8"))

        nonce_bytes = self._nonce.to_bytes(4, byteorder="big")

        data = nonce_bytes + share_bytes

        encrypted_data = self._encrypt(key, data)

        self._logger.debug(f"Encrypted share: {encrypted_data.hex()}")

        return encrypted_data


    def _submit_share(self, session, encrypted_share):
        self._logger.debug("Submitting share")

        request = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "mining.submitShare",
            "params": [
                self._wallet_address,
                self._worker_name,
                self._job_id,
                encrypted_share.hex(),
            ],
        }

        response = session.post(f"http://{self._pool_url}:{self._pool_port}/", json=request)

        if response.status_code != 200:
            raise Exception(f"Failed to submit share: {response.text}")

        result = response.json()["result"]

        self._logger.debug(f"Share submitted: {result}")

        return result


    def submit(self, share):
        self._logger.debug(f"Submitting share: {share}")

        session = requests.Session()

        self._subscribe(session)

        self._get_job(session)

        block_header = self._job["header"]

        difficulty = self._job["difficulty"]

        target = (2**256) // difficulty

        self._logger.debug(f"Target: {target}")

        while self._hash_result == "":
            message = block_header + self._nonce.to_bytes(32, byteorder="little")

            message_hash = sha256(sha256(message).digest()).digest()

            hash_int = int.from_bytes(message_hash, byteorder="little")

            if hash_int < target:
                self._logger.debug(f"Found valid hash: {message_hash.hex()}")

                hash_bytes = message_hash.to_bytes(32, byteorder="big")

                self._hash_result = hash_bytes.hex()

                self._submit_hash(session)

                self._nonce = 0

                self._hash_result = ""

            else:
                self._nonce += 1

                if self._nonce % 100000 == 0:
                    self._logger.debug(f"Nonce: {self._nonce}")

            time.sleep(0.001)

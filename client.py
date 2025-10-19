#!/usr/bin/env python3

import socket
import json
import threading
import argparse
import os
from typing import Dict, Tuple, Optional, List

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    decrypt_session_key,
    generate_aes_key,
    encrypt_session_key,
    encrypt_message,
    decrypt_message,
)

# ANSI color codes for nicer terminal output
class Colors:
    RESET = "\033[0m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    YELLOW = "\033[33m"

class ChatClient:
    def __init__(self, username: str, host: str, port: int):
        self.username = username
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None

        # RSA keys
        self.public_key, self.private_key = generate_rsa_keypair()

        # Known remote public keys and session keys
        self.remote_public_keys: Dict[str, Tuple[int, int]] = {}
        self.session_keys: Dict[str, bytes] = {}

        # Lock for printing/logging to avoid interleaved output
        self.print_lock = threading.Lock()

        # Message log file
        self.log_file = f"messages_{self.username}.json"
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                json.dump([], f)

    def connect(self):
        """Connect to the server and register the user."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        # Register with server
        register_msg = {
            "type": "REGISTER",
            "username": self.username,
            "public_key": serialize_public_key(self.public_key),
        }
        self._send_json(register_msg)

        # Await confirmation
        response = self._recv_json()
        if not response or response.get("type") != "REGISTERED":
            raise RuntimeError(f"Registration failed: {response}")
        with self.print_lock:
            print(f"{Colors.YELLOW}Registered as {self.username}{Colors.RESET}")

        # Start listener thread
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        """Background thread to handle incoming messages from the server."""
        while True:
            try:
                data = self._recv_json()
                if not data:
                    break

                msg_type = data.get("type")

                if msg_type == "SESSION_KEY":
                    # Receive and store session key from another user
                    sender = data.get("from")
                    ciphertext = data.get("data")
                    session_key = decrypt_session_key(ciphertext, self.private_key)
                    self.session_keys[sender] = session_key
                    with self.print_lock:
                        print(f"\n{Colors.YELLOW}Received session key from {sender}{Colors.RESET}")

                elif msg_type == "MESSAGE":
                    sender = data.get("from")
                    ciphertext = data.get("data")
                    session_key = self.session_keys.get(sender)
                    if session_key is None:
                        with self.print_lock:
                            print(f"\nReceived message from {sender} but no session key")
                        continue
                    plaintext = decrypt_message(ciphertext, session_key)
                    with self.print_lock:
                        print("\n" + "-"*40)
                        print(f"Encrypted from {sender}: {ciphertext}")
                        print(f"{Colors.BLUE}Decrypted: {plaintext}{Colors.RESET}")
                        print("-"*40 + "\n")
                    self._append_message_log({
                        "from": sender,
                        "to": self.username,
                        "ciphertext": ciphertext,
                        "plaintext": plaintext,
                    })

                elif msg_type == "PUBLIC_KEY":
                    user = data.get("username")
                    key_data = data.get("public_key")
                    if user and key_data:
                        key_json = json.loads(key_data)
                        self.remote_public_keys[user] = (
                            int(key_json["e"]),
                            int(key_json["n"]),
                        )

                elif msg_type == "ERROR":
                    with self.print_lock:
                        print(f"{Colors.YELLOW}Error from server: {data.get('message')}{Colors.RESET}")

                # Ignore other message types

            except (ConnectionResetError, ConnectionAbortedError):
                break

        with self.print_lock:
            print("Connection closed by server")

    def _send_json(self, obj: dict):
        """Send a JSON object followed by a newline."""
        if not self.socket:
            return
        message = json.dumps(obj).encode() + b"\n"
        try:
            self.socket.sendall(message)
        except (BrokenPipeError, ConnectionResetError):
            with self.print_lock:
                print("Lost connection to server")

    def _recv_json(self) -> Optional[dict]:
        """Receive a JSON message terminated by a newline."""
        if not self.socket:
            return None
        buffer = b""
        while True:
            chunk = self.socket.recv(4096)
            if not chunk:
                return None
            buffer += chunk
            if b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    return json.loads(line.decode())
                except json.JSONDecodeError:
                    return None

    def _append_message_log(self, entry: dict):
        """Append a message entry to the log file."""
        try:
            with open(self.log_file, "r+") as f:
                try:
                    messages: List[dict] = json.load(f)
                except json.JSONDecodeError:
                    messages = []
                messages.append(entry)
                f.seek(0)
                json.dump(messages, f, indent=2)
                f.truncate()
        except IOError:
            with self.print_lock:
                print("Failed to write to message log")

    def fetch_remote_public_key(self, user: str) -> Optional[Tuple[int, int]]:
        """Ensure we have the recipient’s public key; ask the server if needed."""
        if user in self.remote_public_keys:
            return self.remote_public_keys[user]
        request = {"type": "GET_PUBLIC_KEY", "username": user}
        self._send_json(request)
        # Wait up to 5 seconds for the key to arrive via the listener thread
        for _ in range(50):
            if user in self.remote_public_keys:
                return self.remote_public_keys[user]
            threading.Event().wait(0.1)
        with self.print_lock:
            print(f"Timed out waiting for public key of {user}")
        return None

    def send_message(self, recipient: str, text: str):
        """Encrypt and send a message to the recipient."""
        # Ensure a session key exists
        if recipient not in self.session_keys:
            pk = self.fetch_remote_public_key(recipient)
            if pk is None:
                with self.print_lock:
                    print(f"Could not obtain public key for {recipient}")
                return
            session_key = generate_aes_key()
            enc_session = encrypt_session_key(session_key, pk)
            self.session_keys[recipient] = session_key
            payload = {
                "type": "SEND_SESSION_KEY",
                "from": self.username,
                "to": recipient,
                "data": enc_session,
            }
            self._send_json(payload)
            with self.print_lock:
                print(f"{Colors.YELLOW}Sent session key to {recipient}{Colors.RESET}")

        # Encrypt and send the message
        session_key = self.session_keys[recipient]
        ciphertext = encrypt_message(text, session_key)
        payload = {
            "type": "SEND_MESSAGE",
            "from": self.username,
            "to": recipient,
            "data": ciphertext,
        }
        self._send_json(payload)
        self._append_message_log({
            "from": self.username,
            "to": recipient,
            "ciphertext": ciphertext,
            "plaintext": text,
        })
        with self.print_lock:
            print(f"{Colors.GREEN}Sent encrypted message to {recipient}{Colors.RESET}")

    def repl(self):
        """Interactive prompt for sending messages."""
        try:
            while True:
                try:
                    inp = input(f"{Colors.GREEN}{self.username}>{Colors.RESET} ").strip()
                except EOFError:
                    break
                if not inp:
                    continue
                if inp.lower() in {"quit", "exit"}:
                    break
                parts = inp.split(maxsplit=1)
                if len(parts) < 2:
                    print("Usage: <recipient> <message>")
                    continue
                recipient, message = parts[0], parts[1]
                self.send_message(recipient, message)
        finally:
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
            with self.print_lock:
                print("Disconnected")

def main():
    parser = argparse.ArgumentParser(description="Simple E2EE chat client")
    parser.add_argument("--username", required=True, help="Your chat username")
    parser.add_argument("--host", default="127.0.0.1", help="Server hostname")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    args = parser.parse_args()
    client = ChatClient(args.username, args.host, args.port)
    client.connect()
    client.repl()

if __name__ == "__main__":
    main()

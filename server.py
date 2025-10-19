#!/usr/bin/env python3

import socket
import json
import threading
import argparse
from typing import Dict, Tuple

from crypto_utils import deserialize_public_key


class ChatServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        # Mapping from username to (connection, public_key)
        self.clients: Dict[str, Tuple[socket.socket, Tuple[int, int]]] = {}
        # Lock to protect the clients dictionary
        self.lock = threading.Lock()

    def start(self):
        """Start the server and listen for incoming connections."""
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind((self.host, self.port))
        srv_sock.listen()
        print(f"Server listening on {self.host}:{self.port}")
        try:
            while True:
                conn, addr = srv_sock.accept()
                print(f"New connection from {addr}")
                thread = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                thread.start()
        finally:
            srv_sock.close()

    def handle_client(self, conn: socket.socket):
        """Handle messages from a connected client."""
        user = None
        try:
            while True:
                data = self._recv_json(conn)
                if not data:
                    break
                msg_type = data.get("type")
                if msg_type == "REGISTER":
                    username = data.get("username")
                    public_key_enc = data.get("public_key")
                    if not username or not public_key_enc:
                        self._send_json(conn, {"type": "ERROR", "message": "Missing username or public_key"})
                        continue
                    public_key = deserialize_public_key(public_key_enc)
                    with self.lock:
                        self.clients[username] = (conn, public_key)
                    user = username
                    print(f"Registered user {username}")
                    self._send_json(conn, {"type": "REGISTERED"})
                elif msg_type == "GET_PUBLIC_KEY":
                    target = data.get("username")
                    if not target:
                        self._send_json(conn, {"type": "ERROR", "message": "Missing username"})
                        continue
                    with self.lock:
                        entry = self.clients.get(target)
                    if entry:
                        _, pk = entry
                        # Return base64 encoded representation
                        key_data = {
                            "e": str(pk[0]),
                            "n": str(pk[1])
                        }
                        self._send_json(conn, {"type": "PUBLIC_KEY", "username": target, "public_key": json.dumps(key_data)})
                    else:
                        self._send_json(conn, {"type": "ERROR", "message": f"Unknown user {target}"})
                elif msg_type == "SEND_SESSION_KEY":
                    sender = data.get("from")
                    recipient = data.get("to")
                    ciphertext = data.get("data")
                    if not sender or not recipient or not ciphertext:
                        self._send_json(conn, {"type": "ERROR", "message": "Missing fields in SEND_SESSION_KEY"})
                        continue
                    # Log the encrypted session key
                    print(f"Session key from {sender} -> {recipient}: {ciphertext}")
                    self._forward_message("SESSION_KEY", sender, recipient, ciphertext)
                elif msg_type == "SEND_MESSAGE":
                    sender = data.get("from")
                    recipient = data.get("to")
                    ciphertext = data.get("data")
                    if not sender or not recipient or not ciphertext:
                        self._send_json(conn, {"type": "ERROR", "message": "Missing fields in SEND_MESSAGE"})
                        continue
                    # Log the ciphertext message
                    print(f"Ciphertext from {sender} -> {recipient}: {ciphertext}")
                    self._forward_message("MESSAGE", sender, recipient, ciphertext)
                else:
                    self._send_json(conn, {"type": "ERROR", "message": f"Unknown message type {msg_type}"})
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            if user:
                with self.lock:
                    # Remove from registry if still associated with this connection
                    stored = self.clients.get(user)
                    if stored and stored[0] is conn:
                        del self.clients[user]
                print(f"Connection to {user} closed")
            conn.close()

    def _forward_message(self, msg_type: str, sender: str, recipient: str, ciphertext: str):
        """Forward a message to the intended recipient if connected."""
        with self.lock:
            entry = self.clients.get(recipient)
        if entry:
            rec_conn, _ = entry
            payload = {
                "type": msg_type,
                "from": sender,
                "data": ciphertext
            }
            self._send_json(rec_conn, payload)
        else:
            print(f"Recipient {recipient} not connected; dropping message")

    @staticmethod
    def _recv_json(conn: socket.socket):
        """Receive a JSON message terminated by a newline."""
        buffer = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buffer += chunk
            if b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    return json.loads(line.decode())
                except json.JSONDecodeError:
                    print("Failed to decode JSON from client")
                    return None

    @staticmethod
    def _send_json(conn: socket.socket, data: dict):
        """Send a JSON object followed by a newline."""
        try:
            message = json.dumps(data).encode() + b"\n"
            conn.sendall(message)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    parser = argparse.ArgumentParser(description="Simple E2EE chat server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    args = parser.parse_args()
    server = ChatServer(args.host, args.port)
    server.start()


if __name__ == "__main__":
    main()
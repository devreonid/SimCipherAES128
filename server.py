import argparse
import json
import os
import secrets
import socket
import string
import threading

from AES import aes_encrypt

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
CLIENT_IDS = ("alice", "bob")
KEY_ALPHABET = string.ascii_letters + string.digits

def new_ascii_key() -> bytes:
    return "".join(secrets.choice(KEY_ALPHABET) for _ in range(16)).encode("ascii")

class SessionKeys:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current_version = 1
        self._keys = {1: new_ascii_key()}

    def current(self) -> tuple[int, bytes]:
        with self._lock:
            return self._current_version, self._keys[self._current_version]

    def rotate(self, key: bytes) -> int:
        with self._lock:
            self._current_version += 1
            self._keys[self._current_version] = key
            return self._current_version

def receive_line(connection: socket.socket) -> bytes:
    data = bytearray()
    while True:
        chunk = connection.recv(1)
        if not chunk:
            raise ConnectionError("Koneksi ditutup sebelum permintaan lengkap.")
        if chunk == b"\n":
            return bytes(data)
        data.extend(chunk)
        if len(data) > 1_000_000:
            raise ValueError("Permintaan terlalu besar.")

def send_json(connection: socket.socket, payload: dict) -> None:
    connection.sendall(json.dumps(payload, ensure_ascii=True).encode("ascii") + b"\n")

def handle_client(
    connection: socket.socket,
    address: tuple[str, int],
    bootstrap_keys: dict[str, bytes],
    session_keys: SessionKeys,
) -> None:
    try:
        connection.settimeout(10)
        request = json.loads(receive_line(connection).decode("ascii"))
        if not isinstance(request, dict) or request.get("type") != "request_session":
            raise ValueError("Permintaan harus bertipe 'request_session'.")

        alice_id = request.get("alice_id")
        bob_id = request.get("bob_id")
        if alice_id != "alice" or bob_id != "bob":
            raise ValueError("Skenario yang didukung adalah alice meminta sesi dengan bob.")

        version, session_key = session_keys.current()
        ticket_plaintext = json.dumps(
            {"alice_id": alice_id, "bob_id": bob_id,
             "key_version": version, "session_key": session_key.decode("ascii")},
            separators=(",", ":"),
        ).encode("ascii")

        ticket_for_bob = aes_encrypt(ticket_plaintext, bootstrap_keys[bob_id]).hex()
        response_plaintext = json.dumps(
            {"bob_id": bob_id, "key_version": version,
             "session_key": session_key.decode("ascii"), "ticket_for_bob": ticket_for_bob},
            separators=(",", ":"),
        ).encode("ascii")

        response_for_alice = aes_encrypt(response_plaintext, bootstrap_keys[alice_id]).hex()
        send_json(connection, {"wrapped_response": response_for_alice})
        print(f"Kunci sesi versi {version} berhasil dibuat untuk Alice.")
    except (
        ConnectionError, json.JSONDecodeError, OSError, UnicodeDecodeError,
        ValueError, TypeError, AttributeError,
    ) as error:
        try:
            send_json(connection, {"error": f"Permintaan ditolak: {error}"})
        except OSError:
            pass
        print(f"Permintaan dari {address[0]} gagal diproses: {error}")
    finally:
        connection.close()

def key_admin_console(session_keys: SessionKeys) -> None:
    while True:
        try:
            command = input("KDC [set/random/status]: ").strip().lower()
        except EOFError:
            return
        if command == "status":
            version, _ = session_keys.current()
            print(f"Kunci sesi yang aktif: versi {version}.")
        elif command == "random":
            version = session_keys.rotate(new_ascii_key())
            print(f"Kunci acak berhasil dibuat. Versi: {version}.")
        elif command == "set":
            value = input("Kunci sesi ASCII baru (tepat 16 karakter): ")
            if not value.isascii() or len(value) != 16:
                print("Kunci harus 16 karakter ASCII.")
                continue
            version = session_keys.rotate(value.encode("ascii"))
            print(f"Kunci baru berhasil disimpan. Versi: {version}.")
        elif command:
            print("Perintah: set, random, status.")

def main() -> None:
    parser = argparse.ArgumentParser(description="Jalankan pada perangkat KDC.")
    parser.add_argument("--host", default=os.getenv("SIMCIPHER_BIND_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.getenv("SIMCIPHER_PORT", DEFAULT_PORT)))
    args = parser.parse_args()
    bootstrap_keys: dict[str, bytes] = {}
    for client_id in CLIENT_IDS:
        value = os.getenv(f"SIMCIPHER_{client_id.upper()}_BOOTSTRAP_KEY")
        if value is None or not value.isascii() or len(value) != 16:
            parser.error(
                f"Atur SIMCIPHER_{client_id.upper()}_BOOTSTRAP_KEY sebagai "
                "kunci ASCII tepat 16 karakter."
            )
        bootstrap_keys[client_id] = value.encode("ascii")
    if bootstrap_keys["alice"] == bootstrap_keys["bob"]:
        parser.error("Kunci bootstrap Alice dan Bob harus berbeda.")

    session_keys = SessionKeys()

    threading.Thread(target=key_admin_console, args=(session_keys,), daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(10)
        print(f"Server KDC berjalan di {args.host}:{args.port}.")
        print("Perintah: set, random, status.")
        while True:
            connection, address = server.accept()
            threading.Thread(
                target=handle_client,
                args=(connection, address, bootstrap_keys, session_keys),
                daemon=True,
            ).start()

if __name__ == "__main__":
    main()

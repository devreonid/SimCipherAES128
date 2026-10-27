import argparse
import json
import os
import secrets
import socket
import threading

from AES import aes_decrypt, aes_encrypt

DEFAULT_KDC_PORT = 5000
DEFAULT_PEER_PORT = 5001
CLIENT_IDS = ("alice", "bob")

class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: dict[int, bytes] = {}

    def put(self, version: int, key: bytes) -> None:
        with self._lock:
            self._keys[version] = key

    def get(self, version: int) -> bytes | None:
        with self._lock:
            return self._keys.get(version)

    def latest(self) -> tuple[int, bytes] | None:
        with self._lock:
            if not self._keys:
                return None
            version = max(self._keys)
            return version, self._keys[version]

def receive_line(connection: socket.socket) -> bytes:
    data = bytearray()
    while True:
        chunk = connection.recv(1)
        if not chunk:
            raise ConnectionError("Koneksi ditutup sebelum pesan lengkap.")
        if chunk == b"\n":
            return bytes(data)
        data.extend(chunk)
        if len(data) > 1_000_000:
            raise ValueError("Pesan terlalu besar.")

def receive_json(connection: socket.socket) -> dict:
    value = json.loads(receive_line(connection).decode("ascii"))
    if not isinstance(value, dict):
        raise ValueError("Pesan jaringan harus berupa objek JSON.")
    if "error" in value:
        raise ValueError(value["error"])
    return value

def send_json(connection: socket.socket, payload: dict) -> None:
    connection.sendall(json.dumps(payload, ensure_ascii=True).encode("ascii") + b"\n")

def request_session(kdc: tuple[str, int], alice_key: bytes) -> dict:
    with socket.create_connection(kdc, timeout=10) as connection:
        send_json(connection, {"type": "request_session", "alice_id": "alice", "bob_id": "bob"})
        response = receive_json(connection)
    wrapped = bytes.fromhex(response["wrapped_response"])
    plaintext = aes_decrypt(wrapped, alice_key).decode("ascii")
    result = json.loads(plaintext)
    if not isinstance(result, dict) or result.get("bob_id") != "bob":
        raise ValueError("Respons KDC tidak valid.")
    session_key = result["session_key"].encode("ascii")
    if len(session_key) != 16:
        raise ValueError("Kunci sesi dari KDC harus 16 byte ASCII.")
    result["session_key_bytes"] = session_key
    return result

def initiate_handshake(
    kdc: tuple[str, int],
    peer: tuple[str, int],
    alice_bootstrap_key: bytes,
    sessions: SessionStore,
) -> tuple[int, bytes]:

    session_data = request_session(kdc, alice_bootstrap_key)
    version = session_data["key_version"]
    session_key = session_data.pop("session_key_bytes")
    sessions.put(version, session_key)

    with socket.create_connection(peer, timeout=20) as connection:
        connection.settimeout(20)
        send_json(connection, {"type": "ticket", "ticket": session_data["ticket_for_bob"]})
        challenge = receive_json(connection)
        if challenge.get("type") != "challenge" or challenge.get("key_version") != version:
            raise ValueError("Challenge dari Bob tidak valid.")
        nonce = int(aes_decrypt(bytes.fromhex(challenge["ciphertext"]), session_key).decode("ascii"))
        proof = str((nonce - 1) % (1 << 128)).encode("ascii")
        send_json(connection, {
            "type": "proof", "key_version": version,
            "ciphertext": aes_encrypt(proof, session_key).hex(),
        })
    print(f"Handshake berhasil. Versi kunci: {version}.")
    return version, session_key

def handle_peer(
    connection: socket.socket,
    address: tuple[str, int],
    client_id: str,
    bootstrap_key: bytes,
    sessions: SessionStore,
) -> None:
    try:
        with connection:
            connection.settimeout(20)
            request = receive_json(connection)
            if request.get("type") == "ticket" and client_id == "bob":
                ticket_hex = request.get("ticket")
                if not isinstance(ticket_hex, str):
                    raise ValueError("Tiket harus berupa teks hexadecimal.")
                ticket = aes_decrypt(bytes.fromhex(ticket_hex), bootstrap_key)
                ticket_data = json.loads(ticket.decode("ascii"))
                if not isinstance(ticket_data, dict):
                    raise ValueError("Isi tiket tidak valid.")
                if ticket_data.get("alice_id") != "alice" or ticket_data.get("bob_id") != "bob":
                    raise ValueError("Tiket bukan untuk pasangan Alice dan Bob.")
                version = ticket_data["key_version"]
                key_text = ticket_data.get("session_key")
                if type(version) is not int or not isinstance(key_text, str):
                    raise ValueError("Isi tiket tidak valid.")
                session_key = key_text.encode("ascii")
                if len(session_key) != 16:
                    raise ValueError("Isi tiket tidak valid.")
                
                nonce = secrets.randbits(128)
                send_json(connection, {
                    "type": "challenge", "key_version": version,
                    "ciphertext": aes_encrypt(str(nonce).encode("ascii"), session_key).hex(),
                })

                proof = receive_json(connection)
                if proof.get("type") != "proof" or proof.get("key_version") != version:
                    raise ValueError("Respons challenge tidak valid.")
                proof_hex = proof.get("ciphertext")
                if not isinstance(proof_hex, str):
                    raise ValueError("Bukti handshake tidak valid.")
                recovered = aes_decrypt(bytes.fromhex(proof_hex), session_key)
                if recovered != str((nonce - 1) % (1 << 128)).encode("ascii"):
                    raise ValueError("Challenge-response gagal.")
                sessions.put(version, session_key)
                print(f"Handshake dengan Alice berhasil. Versi kunci: {version}.")
                return

            if request.get("type") == "chat":
                version = request.get("key_version")
                session_key = sessions.get(version) if type(version) is int else None
                if session_key is None:
                    raise ValueError("Belum ada kunci sesi untuk pesan ini.")
                ciphertext = request.get("ciphertext")
                if not isinstance(ciphertext, str):
                    raise ValueError("Pesan terenkripsi tidak valid.")
                plaintext = aes_decrypt(bytes.fromhex(ciphertext), session_key)
                message = plaintext.decode("ascii")
                sender = "Alice" if client_id == "bob" else "Bob"
                print(f"\nPesan dari {sender}: {message}")
                return

            raise ValueError("Tipe pesan peer tidak dikenal.")
    except (
        ConnectionError, json.JSONDecodeError, KeyError, OSError,
        UnicodeDecodeError, ValueError, TypeError, AttributeError,
    ) as error:
        print(f"Pesan dari {address[0]} gagal diproses: {error}")

def peer_listener(
    host: str,
    port: int,
    client_id: str,
    bootstrap_key: bytes,
    sessions: SessionStore,
    ready: threading.Event,
) -> None:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(20)
        ready.set()
        print(f"Client {client_id} siap menerima pesan di {host}:{port}.")
        while True:
            connection, address = listener.accept()
            threading.Thread(
                target=handle_peer,
                args=(connection, address, client_id, bootstrap_key, sessions),
                daemon=True,
            ).start()

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Jalankan satu client pada perangkat Alice atau Bob."
    )
    parser.add_argument("client_id", choices=CLIENT_IDS)
    parser.add_argument("--kdc", default=os.getenv("SIMCIPHER_KDC_HOST"),
                        help="IP perangkat KDC (atau SIMCIPHER_KDC_HOST)")
    parser.add_argument("--peer-host", required=True,
                        help="IP perangkat peer: Alice memasukkan IP Bob, Bob memasukkan IP Alice")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=DEFAULT_PEER_PORT)
    parser.add_argument("--kdc-port", type=int, default=int(os.getenv("SIMCIPHER_PORT", DEFAULT_KDC_PORT)))
    parser.add_argument("--peer-port", type=int, default=DEFAULT_PEER_PORT)
    args = parser.parse_args()
    if not args.kdc:
        parser.error("Masukkan IP KDC dengan --kdc atau SIMCIPHER_KDC_HOST.")

    value = os.getenv(f"SIMCIPHER_{args.client_id.upper()}_BOOTSTRAP_KEY")
    if value is None or not value.isascii() or len(value) != 16:
        parser.error(f"SIMCIPHER_{args.client_id.upper()}_BOOTSTRAP_KEY harus tepat 16 karakter ASCII.")
    bootstrap_key = value.encode("ascii")
    sessions = SessionStore()
    listener_ready = threading.Event()

    threading.Thread(
        target=peer_listener,
        args=(args.listen_host, args.listen_port, args.client_id, bootstrap_key, sessions, listener_ready),
        daemon=True,
    ).start()
    if not listener_ready.wait(timeout=5):
        parser.error(f"Gagal membuka listener pada {args.listen_host}:{args.listen_port}.")
    peer = (args.peer_host, args.peer_port)
    kdc = (args.kdc, args.kdc_port)

    active_version: int | None = None
    try:
        if args.client_id == "alice":

         active_version, _ = initiate_handshake(kdc, peer, bootstrap_key, sessions)
        else:
            print("Menunggu Alice memulai handshake...")
        
        while True:
            message = input(f"{args.client_id}> ")
            command = message.strip().lower()
            if command == "/quit":
                break
            if command == "/rekey":
                if args.client_id != "alice":
                    print("Perintah /rekey hanya bisa digunakan oleh Alice.")
                    continue
                active_version, _ = initiate_handshake(kdc, peer, bootstrap_key, sessions)
                continue
            if not message.isascii():
                print("Pesan harus ASCII.")
                continue
            if args.client_id == "bob":
                latest = sessions.latest()
                active_version = latest[0] if latest else None
            if active_version is None:
                print("Belum ada kunci sesi. Tunggu Alice.")
                continue
            session_key = sessions.get(active_version)
            if session_key is None:
                print("Kunci sesi tidak ada. Minta Alice memakai /rekey.")
                active_version = None
                continue
            encrypted = aes_encrypt(message.encode("ascii"), session_key)
            with socket.create_connection(peer, timeout=10) as connection:
                send_json(connection, {
                    "type": "chat", "key_version": active_version,
                    "ciphertext": encrypted.hex(),
                })
                print("Pesan berhasil dikirim.")
    except (OSError, ConnectionError, KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        print(f"Program berhenti karena terjadi kesalahan: {error}")

if __name__ == "__main__":
    main()

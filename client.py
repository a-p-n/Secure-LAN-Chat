import asyncio
import websockets
import argparse
import os
import subprocess
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

SERVER_URL = "ws://127.0.0.1:8000/ws"
DOWNLOAD_DIR = os.path.expanduser("~/Downloads/my_files")

async def secure_handshake(ws):
    server_rsa_pub = RSA.import_key(await ws.recv())
    server_eph_bytes = await ws.recv()
    signature = await ws.recv()
    
    h = SHA256.new(server_eph_bytes)
    pss.new(server_rsa_pub).verify(h, signature)

    server_eph_pub = ECC.import_key(server_eph_bytes.decode('utf-8'))
    client_eph_key = ECC.generate(curve='P-256')
    await ws.send(client_eph_key.public_key().export_key(format='PEM').encode('utf-8'))

    shared_point = server_eph_pub.pointQ * client_eph_key.d
    shared_secret = shared_point.x.to_bytes()
    session_key = HKDF(shared_secret, 32, salt=b'', hashmod=SHA256)
    return session_key

async def authenticate(ws, session_key, username):
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(username.encode('utf-8'))
    await ws.send(cipher.nonce + tag + ciphertext)

async def run_daemon():
    print("[DAEMON]: Starting secure background listener...")
    async with websockets.connect(SERVER_URL) as ws:
        session_key = await secure_handshake(ws)
        await authenticate(ws, session_key, "laptop-daemon")
        
        while True:
            try:
                payload = await ws.recv()
                nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
                
                cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                filepath = os.path.join(DOWNLOAD_DIR, "secure_transfer_file")
                with open(filepath, "wb") as f:
                    f.write(plaintext)
                
                subprocess.run(['notify-send', 'Secure Transfer', 'New file received in Downloads!'])
                print(f"[DAEMON]: File saved to {filepath}")
                
            except Exception as e:
                print(f"[DAEMON]: Error receiving data - {e}")
                break

async def send_file(filepath):
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    print(f"[CLI]: Encrypting and sending {filepath}...")
    async with websockets.connect(SERVER_URL) as ws:
        session_key = await secure_handshake(ws)
        await authenticate(ws, session_key, "laptop-cli")
        
        with open(filepath, "rb") as f:
            file_data = f.read()
            
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        await ws.send(cipher.nonce + tag + ciphertext)
        print("[CLI]: Transfer complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure LAN Chat / File Transfer")
    parser.add_argument("file", nargs="?", help="The file to send. If omitted, runs in daemon mode.")
    args = parser.parse_args()

    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    if args.file:
        asyncio.run(send_file(args.file))
    else:
        asyncio.run(run_daemon())
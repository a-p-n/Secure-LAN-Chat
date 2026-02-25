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
import struct

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
                
                msg_type = plaintext[0]
                
                if msg_type == 0: # Text Broadcast
                    print(plaintext[1:].decode('utf-8'))
                    
                elif msg_type == 1: # File Transfer
                    name_len = struct.unpack('!I', plaintext[1:5])[0]
                    
                    filename = plaintext[5 : 5+name_len].decode('utf-8')
                    file_data = plaintext[5+name_len :]
                    
                    safe_filename = os.path.basename(filename)
                    filepath = os.path.join(DOWNLOAD_DIR, safe_filename)
                    
                    with open(filepath, "wb") as f:
                        f.write(file_data)
                    
                    subprocess.run(['notify-send', 'Secure Transfer', f'Received: {safe_filename}'])
                    print(f"[DAEMON]: Saved {safe_filename}")
                
            except Exception as e:
                print(f"[DAEMON]: Error receiving data - {e}")
                break

async def send_file(filepath):
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    filename = os.path.basename(filepath)
    print(f"[CLI]: Encrypting and sending {filename}...")
    
    async with websockets.connect(SERVER_URL) as ws:
        session_key = await secure_handshake(ws)
        await authenticate(ws, session_key, "laptop-cli")
        
        name_bytes = filename.encode('utf-8')
        name_len_bytes = struct.pack('!I', len(name_bytes))
        
        with open(filepath, "rb") as f:
            file_data = f.read()
            
        payload_to_encrypt = b'\x01' + name_len_bytes + name_bytes + file_data
            
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload_to_encrypt)
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
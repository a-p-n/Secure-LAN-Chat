import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()
app.mount("/static", StaticFiles(directory="web"), name="static")

@app.get("/")
async def get_index():
    return FileResponse("web/index.html")

clients = {} 

SERVER_IDENTITY = RSA.generate(2048)

async def broadcast(message_bytes: bytes, sender_ws: WebSocket, sender_name: str = ""):
    disconnected = []
    for ws, client_data in clients.items():
        if ws == sender_ws:
            continue
            
        if sender_name == "laptop-cli" and client_data['name'] == "laptop-daemon":
            continue
            
        try:
            key = client_data['key']
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(message_bytes)
            
            payload = cipher.nonce + tag + ciphertext
            await ws.send_bytes(payload)
        except Exception as e:
            print(f"[SERVER]: Error broadcasting: {e}")
            disconnected.append(ws)
            
    for ws in disconnected:
        del clients[ws]

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print(f"[SERVER]: New device connecting...")
    
    try:
        await websocket.send_bytes(SERVER_IDENTITY.publickey().export_key())
        
        server_eph_key = ECC.generate(curve='P-256')
        server_eph_pub_bytes = server_eph_key.public_key().export_key(format='PEM').encode('utf-8')
        
        h = SHA256.new(server_eph_pub_bytes)
        signature = pss.new(SERVER_IDENTITY).sign(h)
        
        await websocket.send_bytes(server_eph_pub_bytes)
        await websocket.send_bytes(signature)
        
        client_eph_bytes = await websocket.receive_bytes()
        client_eph_pub = ECC.import_key(client_eph_bytes.decode('utf-8'))
        
        shared_point = client_eph_pub.pointQ * server_eph_key.d
        shared_secret = shared_point.x.to_bytes()
        session_key = HKDF(shared_secret, 32, salt=b'', hashmod=SHA256)
        
        payload = await websocket.receive_bytes()
        nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
        
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        username = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
            
        print(f"[SERVER]: Verified device '{username}'")
        clients[websocket] = {'key': session_key, 'name': username}
        
        announcement = b'\x00' + f"Server: {username} has connected.".encode('utf-8')
        await broadcast(announcement, websocket)

        while True:
            payload = await websocket.receive_bytes()
            nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
            
            try:
                cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                msg_type = plaintext[0]

                if msg_type == 0:
                    msg_str = plaintext[1:].decode('utf-8', errors='ignore')
                    print(f"[{username}]: {msg_str}")
                    
                    fwd_payload = b'\x00' + f"{username}: {msg_str}".encode('utf-8')
                    await broadcast(fwd_payload, websocket, username)
                    
                elif msg_type == 1:
                    print(f"[{username}]: Transmitted File ({len(plaintext)} bytes)")
                    
                    await broadcast(plaintext, websocket, username)
                    
            except ValueError:
                print(f"[SERVER]: Integrity Check Failed for {username}!")
                break

    except WebSocketDisconnect:
        print("[SERVER]: Device disconnected cleanly.")
    except Exception as e:
        print(f"[SERVER]: Connection Error: {e}")
    finally:
        if websocket in clients:
            del clients[websocket]
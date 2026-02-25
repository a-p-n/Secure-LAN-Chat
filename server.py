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

async def broadcast(message: str, sender_ws: WebSocket):
    disconnected = []
    for ws, client_data in clients.items():
        if ws == sender_ws:
            continue
        try:
            key = client_data['key']
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
            
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
        
        await broadcast(f"Server: {username} has connected to the secure relay.", websocket)

        while True:
            payload = await websocket.receive_bytes()
            nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
            
            try:
                cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                msg_str = plaintext.decode('utf-8', errors='ignore')
                print(f"[{username}]: Transmitted {len(plaintext)} bytes")
                
                await broadcast(f"{username}: {msg_str}", websocket)
                
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
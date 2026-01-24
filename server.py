import socket
import threading
import struct
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

clients = {}  # Format: {addr: {'socket': sock, 'key': aes_key, 'name': username}}
clients_lock = threading.Lock()

SERVER_IDENTITY = RSA.generate(2048)

def send_packet(sock, data):
    length = struct.pack('!I', len(data))
    sock.sendall(length + data)

def recv_packet(sock):
    len_bytes = sock.recv(4)
    if not len_bytes: return None
    length = struct.unpack('!I', len_bytes)[0]
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk: return None
        data += chunk
    return data

def broadcast(message, sender_addr):
    with clients_lock:
        for addr, client_data in clients.items():
            if addr == sender_addr:
                continue
            try:
                key = client_data['key']
                cipher = AES.new(key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
                
                payload = cipher.nonce + tag + ciphertext
                send_packet(client_data['socket'], payload)
            except Exception as e:
                print(f"[SERVER]: Error broadcasting to {addr}: {e}")

def handle_client(client_socket, addr):
    print(f"[SERVER]: New connection from {addr}")
    try:
        send_packet(client_socket, SERVER_IDENTITY.publickey().export_key())
        
        server_eph_key = ECC.generate(curve='P-256')
        server_eph_pub_bytes = server_eph_key.public_key().export_key(format='PEM')
        
        h = SHA256.new(server_eph_pub_bytes.encode('utf-8'))
        signature = pss.new(SERVER_IDENTITY).sign(h)
        
        send_packet(client_socket, server_eph_pub_bytes.encode('utf-8'))
        send_packet(client_socket, signature)
        
        client_eph_bytes = recv_packet(client_socket)
        client_eph_pub = ECC.import_key(client_eph_bytes)
        
        shared_point = client_eph_pub.pointQ * server_eph_key.d
        shared_secret = shared_point.x.to_bytes()
        session_key = HKDF(shared_secret, 32, salt=b'', hashmod=SHA256)
        
        payload = recv_packet(client_socket)
        nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
        
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        username = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        
        print(f"[SERVER]: Verified user '{username}' from {addr}")
        
        with clients_lock:
            clients[addr] = {'socket': client_socket, 'key': session_key, 'name': username}
        
        broadcast(f"Server: {username} has joined the chat!", addr)

        while True:
            payload = recv_packet(client_socket)
            if not payload: break
            
            nonce = payload[:16]
            tag = payload[16:32]
            ciphertext = payload[32:]
            
            try:
                cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                msg_str = plaintext.decode('utf-8')
                
                print(f"[{username}]: {msg_str}")
                
                broadcast(f"{username}: {msg_str}", addr)
                
            except ValueError:
                print(f"[SERVER]: Integrity Check Failed for {username}!")
                break

    except Exception as e:
        print(f"[SERVER]: Error with {addr}: {e}")
    finally:
        with clients_lock:
            if addr in clients:
                del clients[addr]
        client_socket.close()

def run_server():
    SERVER_HOST = '0.0.0.0'
    SERVER_PORT = 65432
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"[SERVER]: Listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client_sock, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client_sock, addr))
        t.start()

if __name__ == "__main__":
    run_server()
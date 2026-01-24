import socket
import threading
import struct
import os
import sys
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

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

def receive_messages(sock, key):
    try:
        while True:
            payload = recv_packet(sock)
            if not payload:
                print("\n[CLIENT]: Disconnected.")
                os._exit(0)
            
            nonce, tag, ciphertext = payload[:16], payload[16:32], payload[32:]
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                sys.stdout.write(f"\r{plaintext.decode('utf-8')}\n")
                sys.stdout.write("[YOU]: ")
                sys.stdout.flush()
            except ValueError:
                print("\n[CLIENT]: Integrity Check Failed!")
    except OSError:
        pass

def run_client():
    SERVER_HOST = '10.121.119.79' 
    SERVER_PORT = 65432

    my_username = input("Enter your username: ")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
    except:
        print("Connection refused.")
        return

    print(f"[CLIENT]: Connected...")

    try:
        server_rsa_pub = RSA.import_key(recv_packet(sock))
        
        server_eph_bytes = recv_packet(sock)
        signature = recv_packet(sock)
        
        h = SHA256.new(server_eph_bytes)
        try:
            pss.new(server_rsa_pub).verify(h, signature)
        except:
            print("[CLIENT]: Verification FAILED!")
            return

        server_eph_pub = ECC.import_key(server_eph_bytes)
        client_eph_key = ECC.generate(curve='P-256')
        send_packet(sock, client_eph_key.public_key().export_key(format='PEM').encode('utf-8'))

        shared_point = server_eph_pub.pointQ * client_eph_key.d
        shared_secret = shared_point.x.to_bytes()
        session_key = HKDF(shared_secret, 32, salt=b'', hashmod=SHA256)
        
    except Exception as e:
        print(f"[CLIENT]: Handshake failed: {e}")
        return

    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(my_username.encode('utf-8'))
    send_packet(sock, cipher.nonce + tag + ciphertext)
    
    print(f"[CLIENT]: Joined chat as '{my_username}'")

    recv_thread = threading.Thread(target=receive_messages, args=(sock, session_key))
    recv_thread.daemon = True
    recv_thread.start()
    
    sys.stdout.write("[YOU]: ")
    sys.stdout.flush()

    while True:
        msg = input()
        if not msg: break
        
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")
        print(f"[YOU]: {msg}")
        
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
        send_packet(sock, cipher.nonce + tag + ciphertext)
        
        sys.stdout.write("[YOU]: ")
        sys.stdout.flush()

    sock.close()

if __name__ == "__main__":
    run_client()
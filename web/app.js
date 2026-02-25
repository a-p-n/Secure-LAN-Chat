const statusEl = document.getElementById('status');
const fileInput = document.getElementById('fileInput');
const sendBtn = document.getElementById('sendBtn');

let ws;
let sessionKey = null;

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL = `${wsProtocol}//${window.location.host}/ws`;

async function connectAndHandshake() {
    ws = new WebSocket(WS_URL);
    ws.binaryType = "arraybuffer";

    ws.onopen = () => {
        statusEl.innerText = "Connected! Performing Cryptographic Handshake...";
    };

    ws.onmessage = async (event) => {
        if (!sessionKey) {
            try {
                const rawKey = new Uint8Array(32); crypto.getRandomValues(rawKey);
                sessionKey = await crypto.subtle.importKey("raw", rawKey, {name: "AES-GCM"}, false, ["encrypt", "decrypt"]);
                
                await authenticate("phone-pwa");
                
                statusEl.innerText = "Secure Tunnel Established. Ready to transfer.";
                statusEl.style.color = "#4CAF50";
                sendBtn.disabled = false;
            } catch (err) {
                statusEl.innerText = "Handshake Failed!";
                statusEl.style.color = "red";
                console.error(err);
            }
        } else {
            console.log("Received encrypted payload from server.");
        }
    };
}

async function authenticate(username) {
    const enc = new TextEncoder();
    const data = enc.encode(username);
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, sessionKey, data);
    
    const payload = new Uint8Array(nonce.length + ciphertext.byteLength);
    payload.set(nonce, 0);
    payload.set(new Uint8Array(ciphertext), nonce.length);
    
    ws.send(payload);
}

async function encryptAndSendFile(file) {
    if (!sessionKey) return alert("Not securely connected yet!");
    statusEl.innerText = `Encrypting ${file.name}...`;

    const arrayBuffer = await file.arrayBuffer();
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    
    try {
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, sessionKey, arrayBuffer);
        
        const payload = new Uint8Array(nonce.length + ciphertext.byteLength);
        payload.set(nonce, 0);
        payload.set(new Uint8Array(ciphertext), nonce.length);
        
        ws.send(payload);
        statusEl.innerText = `Sent ${file.name} securely!`;
        setTimeout(() => { statusEl.innerText = "Secure Tunnel Established. Ready to transfer."; }, 3000);
    } catch (err) {
        console.error("Encryption failed", err);
        statusEl.innerText = "Encryption Failed!";
    }
}

sendBtn.addEventListener('click', () => {
    if (fileInput.files.length > 0) {
        encryptAndSendFile(fileInput.files[0]);
    }
});

navigator.serviceWorker.addEventListener('message', event => {
    if (event.data && event.data.type === 'SHARED_FILE') {
        console.log("Caught file from WhatsApp/Share Menu!");
        encryptAndSendFile(event.data.file);
    }
});

window.onload = connectAndHandshake;

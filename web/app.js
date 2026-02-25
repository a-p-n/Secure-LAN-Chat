const statusEl = document.getElementById('status');
const fileInput = document.getElementById('fileInput');
const sendBtn = document.getElementById('sendBtn');

let ws;
let sessionKey = null;

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL = `${wsProtocol}//${window.location.host}/ws`;

function pemToArrayBuffer(pem) {
    const b64 = pem.replace(/(-----(BEGIN|END).*-----|\n|\r)/g, '');
    const binary = window.atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function arrayBufferToPem(buffer, type) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    const b64 = window.btoa(binary);
    return `-----BEGIN ${type}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${type}-----`;
}

async function connectAndHandshake() {
    ws = new WebSocket(WS_URL);
    ws.binaryType = "arraybuffer";

    let handshakeState = 0;
    let serverRsaKeyBytes, serverEccKeyBytes, signatureBytes;

    ws.onopen = () => {
        statusEl.innerText = "Connected! Performing Cryptographic Handshake...";
    };

    ws.onmessage = async (event) => {
        if (!sessionKey) {
            if (handshakeState === 0) {
                serverRsaKeyBytes = event.data;
                handshakeState++;
            } else if (handshakeState === 1) {
                serverEccKeyBytes = event.data;
                handshakeState++;
            } else if (handshakeState === 2) {
                signatureBytes = event.data;
                handshakeState++;
                await processRealHandshake(serverRsaKeyBytes, serverEccKeyBytes, signatureBytes);
            }
        } else {
            await handleIncomingData(event.data);
        }
    }
}

async function handleIncomingData(encryptedBuffer) {
    try {
        const payload = new Uint8Array(encryptedBuffer);
        
        const nonce = payload.slice(0, 16);
        const tag = payload.slice(16, 32);
        const ciphertext = payload.slice(32);

        const cipherBuffer = new Uint8Array(ciphertext.length + tag.length);
        cipherBuffer.set(ciphertext, 0);
        cipherBuffer.set(tag, ciphertext.length);

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce },
            sessionKey,
            cipherBuffer
        );
        
        const decryptedBytes = new Uint8Array(decryptedBuffer);
        const msgType = decryptedBytes[0];
        
        if (msgType === 1) {
            const dataView = new DataView(decryptedBuffer);
            const nameLen = dataView.getUint32(1, false); 
            
            const nameBytes = decryptedBytes.slice(5, 5 + nameLen);
            const filename = new TextDecoder().decode(nameBytes);
            const fileData = decryptedBytes.slice(5 + nameLen);
            
            statusEl.innerText = `Decrypting ${filename}...`;

            const blob = new Blob([fileData]);
            const url = window.URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filename;
            
            document.body.appendChild(a);
            a.click();
            
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            statusEl.innerText = `Received: ${filename}`;
            setTimeout(() => { statusEl.innerText = "Secure Tunnel Established. Ready to transfer."; }, 4000);
            
        } else if (msgType === 0) {
            const textMsg = new TextDecoder().decode(decryptedBytes.slice(1));
            console.log("Secure Message:", textMsg);
        }
        
    } catch (err) {
        console.error("Decryption failed:", err);
        statusEl.innerText = "Failed to decrypt incoming file.";
    }
}

async function processRealHandshake(rsaBytes, eccBytes, sigBytes) {
    try {
        const dec = new TextDecoder();
        
        const rsaPem = dec.decode(rsaBytes);
        const rsaDer = pemToArrayBuffer(rsaPem);
        const rsaKey = await crypto.subtle.importKey(
            "spki", rsaDer, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]
        );

        const isValid = await crypto.subtle.verify(
            { name: "RSA-PSS", saltLength: 32 }, rsaKey, sigBytes, eccBytes
        );
        if (!isValid) throw new Error("RSA Signature Invalid!");

        const eccPem = dec.decode(eccBytes);
        const eccDer = pemToArrayBuffer(eccPem);
        const serverEccKey = await crypto.subtle.importKey(
            "spki", eccDer, { name: "ECDH", namedCurve: "P-256" }, false, []
        );

        const clientEccKey = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
        );

        const clientEccDer = await crypto.subtle.exportKey("spki", clientEccKey.publicKey);
        const clientEccPem = arrayBufferToPem(clientEccDer, "PUBLIC KEY");
        ws.send(new TextEncoder().encode(clientEccPem));

        const sharedSecret = await crypto.subtle.deriveBits(
            { name: "ECDH", public: serverEccKey }, clientEccKey.privateKey, 256
        );

        const hkdfKey = await crypto.subtle.importKey(
            "raw", sharedSecret, "HKDF", false, ["deriveKey"]
        );
        sessionKey = await crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new Uint8Array(0) },
            hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
        );

        await authenticate("phone-pwa");

        statusEl.innerText = "Secure Tunnel Established. Ready to transfer.";
        statusEl.style.color = "#4CAF50";
        sendBtn.disabled = false;
    } catch (err) {
        statusEl.innerText = "Handshake Failed!";
        statusEl.style.color = "red";
        console.error(err);
    }
}

async function authenticate(username) {
    const data = new TextEncoder().encode(username);
    await encryptAndSendRaw(data);
}

async function encryptAndSendFile(file) {
    if (!sessionKey) return alert("Not securely connected yet!");
    statusEl.innerText = `Encrypting ${file.name}...`;

    try {
        const arrayBuffer = await file.arrayBuffer();
        const fileBytes = new Uint8Array(arrayBuffer);
        
        const nameBytes = new TextEncoder().encode(file.name);
        const nameLen = nameBytes.length;

        const payloadToEncrypt = new Uint8Array(1 + 4 + nameLen + fileBytes.length);
        const dataView = new DataView(payloadToEncrypt.buffer);
        
        payloadToEncrypt[0] = 1;
        dataView.setUint32(1, nameLen, false);
        payloadToEncrypt.set(nameBytes, 5);
        payloadToEncrypt.set(fileBytes, 5 + nameLen);

        await encryptAndSendRaw(payloadToEncrypt.buffer);
        
        statusEl.innerText = `Sent ${file.name} securely!`;
        setTimeout(() => { statusEl.innerText = "Secure Tunnel Established. Ready to transfer."; }, 3000);
    } catch (err) {
        console.error("Encryption failed", err);
        statusEl.innerText = "Encryption Failed!";
    }
}

async function encryptAndSendRaw(buffer) {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, sessionKey, buffer);
    const cipherBytes = new Uint8Array(cipherBuffer);
    
    const actualCiphertextLen = cipherBytes.length - 16;
    const ciphertext = cipherBytes.slice(0, actualCiphertextLen);
    const tag = cipherBytes.slice(actualCiphertextLen);

    const payload = new Uint8Array(16 + 16 + actualCiphertextLen);
    payload.set(nonce, 0);
    payload.set(tag, 16);
    payload.set(ciphertext, 32);
    
    ws.send(payload);
}

sendBtn.addEventListener('click', () => {
    if (fileInput.files.length > 0) encryptAndSendFile(fileInput.files[0]);
});

navigator.serviceWorker.addEventListener('message', event => {
    if (event.data && event.data.type === 'SHARED_FILE') {
        encryptAndSendFile(event.data.file);
    }
});

window.onload = connectAndHandshake;
async function generateKeys() {
    const response = await fetch('/generate_keys', { method: 'POST' });
    const data = await response.json();
    document.getElementById('output').textContent = `Sender Public Key:\n${data.public_key_sender}\n\nRecipient Public Key:\n${data.public_key_recipient}`;
}

async function encryptEmail() {
    const email_content = document.getElementById('email_content').value;
    const response = await fetch('/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_content })
    });
    const data = await response.json();
    document.getElementById('output').textContent = `Nonce:\n${data.nonce}\n\nCiphertext:\n${data.ciphertext}`;
}

async function decryptEmail() {
    const nonce = prompt('Enter the nonce:');
    const ciphertext = prompt('Enter the ciphertext:');
    const response = await fetch('/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nonce, ciphertext })
    });
    const data = await response.json();
    document.getElementById('output').textContent = `Decrypted Email Content:\n${data.email_content}`;
}

async function signEmail() {
    const email_content = document.getElementById('email_content').value;
    const response = await fetch('/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_content })
    });
    const data = await response.json();
    document.getElementById('output').textContent = `Signature:\n${data.signature}`;
}

async function verifySignature() {
    const email_content = document.getElementById('email_content').value;
    const signature = prompt('Enter the signature:');
    const response = await fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_content, signature })
    });
    const data = await response.json();
    document.getElementById('output').textContent = `Signature valid: ${data.valid}`;
}

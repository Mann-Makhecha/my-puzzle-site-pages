const FILES = [
  "java_chapter1-2_FillInTheBlanks.pdf.enc",
  "java_chapter1-2_MCQ.pdf.enc",
  "java_chapter1-2_oneword.pdf.enc",
  "java_chapter1-2_TrueFalse.pdf.enc",
];

// Decrypt AES-GCM encrypted file (used for both check.txt.enc and PDFs)
async function decryptFile(fileUrl, password) {
  const resp = await fetch(fileUrl);
  const data = new Uint8Array(await resp.arrayBuffer());

  // Read IV length (1 byte)
  const ivLength = data[0];
  const iv = data.slice(1, 1 + ivLength);
  const salt = data.slice(1 + ivLength, 1 + ivLength + 16);
  const ciphertext = data.slice(1 + ivLength + 16);

  // Derive key
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // Decrypt
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(decrypted);
}

// Verify password using check.txt.enc
async function verifyPassword(password) {
  try {
    const decrypted = await decryptFile("check.txt.enc", password);
    const text = new TextDecoder().decode(decrypted).trim();
    return text === "OK";
  } catch {
    return false;
  }
}

// Trigger PDF download
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Handle Unlock Button
document.getElementById("unlockBtn").addEventListener("click", async () => {
  const ans = document.getElementById("answer").value.trim();
  const status = document.getElementById("status");
  const downloads = document.getElementById("downloads");

  status.textContent = "Checking...";
  downloads.innerHTML = "";

  const valid = await verifyPassword(ans);

  if (!valid) {
    status.textContent = "❌ Wrong answer!";
    return;
  }

  status.textContent = "✅ Correct! Unlocking downloads...";

  FILES.forEach(file => {
    const btn = document.createElement("button");
    btn.textContent = `Download ${file.replace(".pdf.enc", ".pdf")}`;
    btn.style.display = "block";
    btn.style.margin = "5px auto";
    btn.onclick = async () => {
      try {
        const decrypted = await decryptFile(file, ans);
        const blob = new Blob([decrypted], { type: "application/pdf" });
        downloadBlob(blob, file.replace(".pdf.enc", ".pdf"));
      } catch (err) {
        alert("Decryption failed. Wrong key or corrupted file.");
      }
    };
    downloads.appendChild(btn);
  });
});

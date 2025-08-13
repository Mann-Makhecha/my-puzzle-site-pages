// encrypt/encrypt.js
// Usage (Windows CMD, one line):
// node encrypt/encrypt.js ENCAPSULATION public pdfs/java_chapter1-2_FillInTheBlanks.pdf pdfs/java_chapter1-2_MCQ.pdf pdfs/java_chapter1-2_oneword.pdf pdfs/java_chapter1-2_TrueFalse.pdf

const fs = require("fs");
const path = require("path");
const { webcrypto } = require("crypto");
const { subtle } = webcrypto;
const getRandomValues = (arr) => webcrypto.getRandomValues(arr); // ✅ FIXED binding

const MAGIC = new TextEncoder().encode("JSPDFENC"); // 7 bytes
const VERSION = new Uint8Array([1]); // 1 byte
const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITER = 250000;

async function deriveKey(passwordUtf8, salt) {
  const keyMat = await subtle.importKey(
    "raw",
    passwordUtf8,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
    keyMat,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function u16(n) {
  const b = new Uint8Array(2);
  b[0] = (n >>> 8) & 0xff;
  b[1] = n & 0xff;
  return b;
}

async function encryptFile(password, outDir, inPath) {
  const enc = new TextEncoder();
  const passwordUtf8 = enc.encode(password);

  const salt = new Uint8Array(SALT_LEN);
  getRandomValues(salt);
  const iv = new Uint8Array(IV_LEN);
  getRandomValues(iv);

  const key = await deriveKey(passwordUtf8, salt);

  const data = fs.readFileSync(inPath);
  const meta = {
    name: path.basename(inPath),
    mime: "application/pdf",
    ts: Date.now()
  };
  const metaBytes = enc.encode(JSON.stringify(meta));
  const metaLen = u16(metaBytes.byteLength);

  const ciphertext = new Uint8Array(
    await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: metaBytes },
      key,
      data
    )
  );

  const out = new Uint8Array(
    MAGIC.length + VERSION.length + SALT_LEN + IV_LEN + 2 + metaBytes.length + ciphertext.length
  );
  let off = 0;
  out.set(MAGIC, off); off += MAGIC.length;
  out.set(VERSION, off); off += VERSION.length;
  out.set(salt, off); off += SALT_LEN;
  out.set(iv, off); off += IV_LEN;
  out.set(metaLen, off); off += 2;
  out.set(metaBytes, off); off += metaBytes.length;
  out.set(ciphertext, off);

  const outName = path.basename(inPath) + ".enc";
  const outPath = path.join(outDir, outName);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outPath, out);
  console.log(`Encrypted -> ${outPath}`);
}

(async () => {
  const [,, password, outDir, ...inputs] = process.argv;
  if (!password || !outDir || inputs.length === 0) {
    console.error("Usage: node encrypt.js <PASSWORD> <OUT_DIR> <PDF1> <PDF2> ...");
    process.exit(1);
  }
  for (const p of inputs) {
    if (!fs.existsSync(p)) {
      console.error(`Missing file: ${p}`);
      continue;
    }
    await encryptFile(password, outDir, p);
  }
  console.log("Done.");
})();

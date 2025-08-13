// main.js (secure; uses Web Crypto to match encrypt/encrypt.js format)
// - No hard-coded password
// - Verifies by decrypting check.txt.enc (expected plaintext: "OK")

const FILES = [
  "java_chapter1-2_FillInTheBlanks.pdf.enc",
  "java_chapter1-2_MCQ.pdf.enc",
  "java_chapter1-2_oneword.pdf.enc",
  "java_chapter1-2_TrueFalse.pdf.enc",
];

const CHECK_FILE = "check.txt.enc"; // must be created via encrypt/encrypt.js with plaintext "OK"
const MAGIC_STR = "JSPDFENC";
const MAGIC = new TextEncoder().encode(MAGIC_STR);
const PBKDF2_ITER = 250000;

const te = new TextEncoder();
const td = new TextDecoder();

function be16(b0, b1) { return (b0 << 8) | b1; }

async function deriveKeyFromPassword(passText, salt) {
  const passBytes = te.encode(passText);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", passBytes, "PBKDF2", false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  return key;
}

// Parse the custom file format and return { meta, iv, salt, ctUint8 }
function parseEncFile(bytes) {
  // bytes: Uint8Array
  let off = 0;
  // check magic
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[off + i] !== MAGIC[i]) throw new Error("Bad magic");
  }
  off += MAGIC.length;
  const ver = bytes[off++]; if (ver !== 1) throw new Error("Unsupported version");
  const salt = bytes.subarray(off, off + 16); off += 16;
  const iv = bytes.subarray(off, off + 12); off += 12;
  const metaLen = be16(bytes[off], bytes[off + 1]); off += 2;
  const metaBytes = bytes.subarray(off, off + metaLen); off += metaLen;
  const metaStr = td.decode(metaBytes);
  const meta = JSON.parse(metaStr);
  const ct = bytes.subarray(off);
  return { salt, iv, metaBytes, meta, ct };
}

async function decryptWithPassword(encBytes, password) {
  const parsed = parseEncFile(encBytes);
  const key = await deriveKeyFromPassword(password, parsed.salt);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: parsed.iv, additionalData: parsed.metaBytes },
    key,
    parsed.ct
  );
  return { meta: parsed.meta, data: new Uint8Array(plain) };
}

async function fetchArrayBuffer(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`Fetch failed: ${path} (${r.status})`);
  return new Uint8Array(await r.arrayBuffer());
}

function saveBlob(bytes, filename, mime = "application/pdf") {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1500);
}

async function tryVerifyPassword(password) {
  try {
    const enc = await fetchArrayBuffer(CHECK_FILE);
    const { meta, data } = await decryptWithPassword(enc, password);
    const txt = new TextDecoder().decode(data).trim();
    return txt === "OK";
  } catch (e) {
    console.debug("verify failed:", e);
    return false;
  }
}

async function setupDownloadButtons(password) {
  const downloads = document.getElementById("downloads");
  downloads.innerHTML = "";
  for (const fname of FILES) {
    const btn = document.createElement("button");
    btn.textContent = `Download ${fname.replace(".pdf.enc", ".pdf")}`;
    btn.style.display = "block";
    btn.style.margin = "8px 0";
    btn.disabled = false;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "Decrypting...";
      try {
        const enc = await fetchArrayBuffer(fname);
        const { meta, data } = await decryptWithPassword(enc, password);
        const outName = meta && meta.name ? meta.name : fname.replace(".enc", "");
        saveBlob(data, outName, meta && meta.mime ? meta.mime : "application/pdf");
        btn.textContent = "Downloaded ✓";
      } catch (err) {
        console.error(err);
        btn.textContent = "Failed ❌";
      } finally {
        setTimeout(() => { btn.disabled = false; btn.textContent = `Download ${fname.replace(".pdf.enc", ".pdf")}`; }, 1500);
      }
    });
    downloads.appendChild(btn);
  }
}

/* UI wiring */
document.getElementById("unlockBtn").addEventListener("click", async () => {
  const ans = (document.getElementById("answer").value || "").trim();
  const status = document.getElementById("status");
  status.textContent = "Verifying…";
  try {
    const ok = await tryVerifyPassword(ans);
    if (!ok) {
      status.textContent = "❌ Incorrect password. Try again.";
      return;
    }
    status.textContent = "✅ Correct! Files unlocked below.";
    await setupDownloadButtons(ans);
  } catch (e) {
    console.error(e);
    status.textContent = "❌ Error (see console).";
  }
});

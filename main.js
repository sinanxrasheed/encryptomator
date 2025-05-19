// Main process for Electron
const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const argon2 = require('argon2');

function createWindow() {
  const win = new BrowserWindow({
    width: 600,
    height: 400,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  win.loadFile('index.html');
}

app.whenReady().then(createWindow);

// IPC handlers for vault creation and reveal disk
ipcMain.handle('select-vault-location', async () => {
  const result = await dialog.showOpenDialog({
    properties: ['openDirectory', 'createDirectory']
  });
  return result.filePaths[0];
});

// IPC handler for file selection
ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog({
    properties: ['openFile']
  });
  return result.filePaths[0];
});

// Helper: Derive key from password using Argon2id
async function deriveKeyArgon2(password, salt) {
  // Argon2id with recommended parameters
  return await argon2.hash(password, {
    type: argon2.argon2id,
    salt,
    memoryCost: 2 ** 16, // 64 MB
    timeCost: 4,
    parallelism: 2,
    hashLength: 32,
    raw: true // get raw buffer for key
  });
}

// Helper: Verify Argon2id hash
async function verifyArgon2(hash, password) {
  return await argon2.verify(hash, password);
}

// Helper: Encrypt sensitive metadata fields
function encryptMetaSensitiveFields(meta, password) {
  const crypto = require('crypto');
  const sensitive = {
    salt: meta.salt,
    hash: meta.hash
  };
  const iv = crypto.randomBytes(12);
  // Derive a key from the password (using PBKDF2 for meta encryption, separate from vault key)
  const key = crypto.pbkdf2Sync(password, Buffer.from(meta.salt, 'hex'), 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(sensitive), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: Buffer.concat([iv, tag, enc]).toString('base64')
  };
}

function decryptMetaSensitiveFields(encrypted, password, saltHex) {
  const crypto = require('crypto');
  const buf = Buffer.from(encrypted, 'base64');
  const iv = buf.slice(0, 12);
  const tag = buf.slice(12, 28);
  const enc = buf.slice(28);
  const key = crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), 100000, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(dec.toString('utf8'));
}

// Helper: Create vault structure and store password hash (Argon2id)
ipcMain.handle('finalize-vault', async (event, { vaultPath, password }) => {
  try {
    const salt = crypto.randomBytes(16);
    const key = await deriveKeyArgon2(password, salt);
    // Store Argon2 hash (encoded, not raw) for verification
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      salt,
      memoryCost: 2 ** 16,
      timeCost: 4,
      parallelism: 2,
      hashLength: 32
    });
    // Encrypt sensitive fields
    const encrypted = encryptMetaSensitiveFields({ salt: salt.toString('hex'), hash }, password);
    const meta = {
      encrypted: encrypted.encrypted,
      created: new Date().toISOString(),
      kdf: 'argon2id'
    };
    fs.writeFileSync(path.join(vaultPath, '.encryptomator.meta.json'), JSON.stringify(meta, null, 2));
    fs.mkdirSync(path.join(vaultPath, 'data'), { recursive: true });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Verify password and unlock vault (Argon2id)
ipcMain.handle('unlock-vault', async (event, { vaultPath, password }) => {
  try {
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath))
      return { success: false, error: 'Vault metadata not found.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    if (meta.kdf === 'argon2id') {
      // Decrypt sensitive fields
      const sensitive = decryptMetaSensitiveFields(meta.encrypted, password, undefined);
      const valid = await argon2.verify(sensitive.hash, password);
      if (!valid) return { success: false, error: 'Invalid password.' };
      return { success: true };
    } else {
      // PBKDF2 legacy vault: verify, then migrate to Argon2id
      const salt = Buffer.from(meta.salt, 'hex');
      const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
      const hash = crypto.createHash('sha256').update(key).digest('hex');
      if (hash !== meta.hash) return { success: false, error: 'Invalid password.' };
      // Migrate: create Argon2id hash and update meta
      const argon2Salt = crypto.randomBytes(16);
      const argon2Hash = await argon2.hash(password, {
        type: argon2.argon2id,
        salt: argon2Salt,
        memoryCost: 2 ** 16,
        timeCost: 4,
        parallelism: 2,
        hashLength: 32
      });
      const newMeta = {
        salt: argon2Salt.toString('hex'),
        hash: argon2Hash,
        created: meta.created,
        migratedFrom: 'pbkdf2',
        kdf: 'argon2id'
      };
      fs.writeFileSync(metaPath, JSON.stringify(newMeta, null, 2));
      return { success: true, migrated: true };
    }
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Derive symmetric key for encryption (Argon2id or PBKDF2)
async function getSymmetricKey(password, meta) {
  if (meta.kdf === 'argon2id') {
    // Decrypt sensitive fields
    const sensitive = decryptMetaSensitiveFields(meta.encrypted, password, undefined);
    const salt = Buffer.from(sensitive.salt, 'hex');
    return await deriveKeyArgon2(password, salt);
  } else {
    const salt = Buffer.from(meta.salt, 'hex');
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  }
}

// Helper: Encrypt a file and store in vault (Location A)
ipcMain.handle('encrypt-file', async (event, { vaultPath, filePath, password }) => {
  try {
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath)) return { success: false, error: 'Vault metadata missing.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    const key = await getSymmetricKey(password, meta);
    // Read file
    const data = fs.readFileSync(filePath);
    // Encrypt using AES-256-GCM (Context7 best practice)
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Generate a random name for the encrypted file
    const randomName = crypto.randomBytes(16).toString('hex');
    // Store as: [iv][tag][encrypted]
    const out = Buffer.concat([iv, tag, encrypted]);
    const outPath = path.join(vaultPath, 'data', randomName + '.enc');
    fs.writeFileSync(outPath, out);
    // Store mapping of randomName to original file name in encrypted index
    const indexPath = path.join(vaultPath, 'data', '.index.json');
    let index = {};
    if (fs.existsSync(indexPath)) {
      const indexEnc = fs.readFileSync(indexPath);
      if (indexEnc.length > 28) {
        const indexIv = indexEnc.slice(0, 12);
        const indexTag = indexEnc.slice(12, 28);
        const indexEncrypted = indexEnc.slice(28);
        const indexDecipher = crypto.createDecipheriv('aes-256-gcm', key, indexIv);
        indexDecipher.setAuthTag(indexTag);
        const indexDecrypted = Buffer.concat([indexDecipher.update(indexEncrypted), indexDecipher.final()]);
        index = JSON.parse(indexDecrypted.toString('utf8'));
      }
    }
    index[randomName + '.enc'] = path.basename(filePath);
    // Encrypt and write the index file
    const indexData = Buffer.from(JSON.stringify(index), 'utf8');
    const indexIv = crypto.randomBytes(12);
    const indexCipher = crypto.createCipheriv('aes-256-gcm', key, indexIv);
    const indexEncrypted = Buffer.concat([indexCipher.update(indexData), indexCipher.final()]);
    const indexTag = indexCipher.getAuthTag();
    const indexOut = Buffer.concat([indexIv, indexTag, indexEncrypted]);
    fs.writeFileSync(indexPath, indexOut);
    // Context7: Log encrypted file path for debugging
    console.log('Encrypted file written:', outPath);
    return { success: true, outPath };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Decrypt a file from vault (Location A) to Location B
ipcMain.handle('decrypt-file', async (event, { vaultPath, encFilePath, password, outDir }) => {
  try {
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath)) return { success: false, error: 'Vault metadata missing.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    const key = await getSymmetricKey(password, meta);
    const enc = fs.readFileSync(encFilePath);
    const iv = enc.slice(0, 12);
    const tag = enc.slice(12, 28);
    const encrypted = enc.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    // Lookup original file name from encrypted index
    const indexPath = path.join(vaultPath, 'data', '.index.json');
    let originalName = path.basename(encFilePath, '.enc');
    if (fs.existsSync(indexPath)) {
      const indexEnc = fs.readFileSync(indexPath);
      if (indexEnc.length > 28) {
        const indexIv = indexEnc.slice(0, 12);
        const indexTag = indexEnc.slice(12, 28);
        const indexEncrypted = indexEnc.slice(28);
        const indexDecipher = crypto.createDecipheriv('aes-256-gcm', key, indexIv);
        indexDecipher.setAuthTag(indexTag);
        const indexDecrypted = Buffer.concat([indexDecipher.update(indexEncrypted), indexDecipher.final()]);
        const index = JSON.parse(indexDecrypted.toString('utf8'));
        const encName = path.basename(encFilePath);
        if (index[encName]) {
          originalName = index[encName];
        }
      }
    }
    const outPath = path.join(outDir, originalName);
    fs.writeFileSync(outPath, decrypted);
    return { success: true, outPath };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Recursively get all files (with relative paths) in a directory
function getAllFiles(dir, baseDir = dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach(file => {
    if (file === 'README.txt' || file.startsWith('.')) return;
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat && stat.isDirectory()) {
      results = results.concat(getAllFiles(filePath, baseDir));
    } else {
      results.push(path.relative(baseDir, filePath));
    }
  });
  return results;
}

// Helper: Reveal Disk - decrypt all files to a temp location and open in Explorer
ipcMain.handle('reveal-disk', async (event, { vaultPath, password, customName }) => {
  try {
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath)) return { success: false, error: 'Vault metadata missing.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    const key = await getSymmetricKey(password, meta);
    const encDir = path.join(vaultPath, 'data');
    if (!fs.existsSync(encDir)) return { success: false, error: 'Encrypted data folder missing.' };
    // Use a subfolder in the parent directory of the vault for decrypted files
    let tempDir;
    const parentDir = path.dirname(vaultPath);
    if (customName) {
      tempDir = path.join(parentDir, customName);
    } else {
      tempDir = path.join(parentDir, 'unlocked');
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    fs.mkdirSync(tempDir);
    // Load index for file name mapping (decrypt index)
    const indexPath = path.join(encDir, '.index.json');
    let index = {};
    if (fs.existsSync(indexPath)) {
      const indexEnc = fs.readFileSync(indexPath);
      if (indexEnc.length > 28) {
        const indexIv = indexEnc.slice(0, 12);
        const indexTag = indexEnc.slice(12, 28);
        const indexEncrypted = indexEnc.slice(28);
        const indexDecipher = crypto.createDecipheriv('aes-256-gcm', key, indexIv);
        indexDecipher.setAuthTag(indexTag);
        const indexDecrypted = Buffer.concat([indexDecipher.update(indexEncrypted), indexDecipher.final()]);
        index = JSON.parse(indexDecrypted.toString('utf8'));
      }
    }
    // Decrypt all .enc files and restore folder structure
    const files = fs.readdirSync(encDir).filter(f => f.endsWith('.enc'));
    let decryptedFiles = [];
    if (files.length === 0) {
      fs.writeFileSync(path.join(tempDir, 'README.txt'), 'This vault is empty. Add files to your encrypted vault to see them here.');
    } else {
      for (const file of files) {
        const encFilePath = path.join(encDir, file);
        const enc = fs.readFileSync(encFilePath);
        if (enc.length < 28) continue; // Not a valid encrypted file
        const iv = enc.slice(0, 12);
        const tag = enc.slice(12, 28);
        const encrypted = enc.slice(28);
        try {
          const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
          decipher.setAuthTag(tag);
          const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
          // Lookup original relative file path from index
          let relPath = path.basename(file, '.enc');
          if (index[file]) {
            relPath = index[file];
          }
          const outPath = path.join(tempDir, relPath);
          fs.mkdirSync(path.dirname(outPath), { recursive: true });
          if (decrypted.length > 0) {
            fs.writeFileSync(outPath, decrypted);
            // Set mtime to match encrypted file
            const { mtime } = fs.statSync(encFilePath);
            fs.utimesSync(outPath, mtime, mtime);
            decryptedFiles.push(relPath);
          }
        } catch (err) {
          // If decryption fails, skip the file and optionally log error
        }
      }
    }
    // Context7: Log decrypted files for debugging
    console.log('Decrypted files:', decryptedFiles);
    // Open the temp directory in Explorer
    shell.openPath(tempDir);
    return { success: true, tempDir, decryptedFiles };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Lock Disk - re-encrypt all files in tempDir and update the vault before deleting tempDir
ipcMain.handle('lock-disk', async (event, { tempDir, vaultPath, password }) => {
  try {
    if (!tempDir || !fs.existsSync(tempDir)) {
      return { success: false, error: 'Temporary directory not found.' };
    }
    // Load vault metadata for salt
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath)) return { success: false, error: 'Vault metadata missing.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    const key = await getSymmetricKey(password, meta);
    const encDir = path.join(vaultPath, 'data');
    // Remove all old encrypted files
    if (fs.existsSync(encDir)) {
      fs.readdirSync(encDir).forEach(f => {
        if (f.endsWith('.enc')) fs.unlinkSync(path.join(encDir, f));
      });
    } else {
      fs.mkdirSync(encDir, { recursive: true });
    }
    // Recursively get all files in tempDir
    const files = getAllFiles(tempDir);
    // Prepare index for random name mapping
    const indexPath = path.join(encDir, '.index.json');
    let index = {};
    if (fs.existsSync(indexPath)) {
      // Decrypt the index file
      const indexEnc = fs.readFileSync(indexPath);
      if (indexEnc.length > 28) {
        const indexIv = indexEnc.slice(0, 12);
        const indexTag = indexEnc.slice(12, 28);
        const indexEncrypted = indexEnc.slice(28);
        const indexDecipher = crypto.createDecipheriv('aes-256-gcm', key, indexIv);
        indexDecipher.setAuthTag(indexTag);
        const indexDecrypted = Buffer.concat([indexDecipher.update(indexEncrypted), indexDecipher.final()]);
        index = JSON.parse(indexDecrypted.toString('utf8'));
      }
    }
    for (const relPath of files) {
      const filePath = path.join(tempDir, relPath);
      if (fs.statSync(filePath).isFile()) {
        const data = fs.readFileSync(filePath);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        const randomName = crypto.randomBytes(16).toString('hex');
        const out = Buffer.concat([iv, tag, encrypted]);
        const outPath = path.join(encDir, randomName + '.enc');
        fs.writeFileSync(outPath, out);
        // Store mapping of randomName to original relative file path in encrypted index
        index[randomName + '.enc'] = relPath;
      }
    }
    // Encrypt and write the index file
    const indexData = Buffer.from(JSON.stringify(index), 'utf8');
    const indexIv = crypto.randomBytes(12);
    const indexCipher = crypto.createCipheriv('aes-256-gcm', key, indexIv);
    const indexEncrypted = Buffer.concat([indexCipher.update(indexData), indexCipher.final()]);
    const indexTag = indexCipher.getAuthTag();
    const indexOut = Buffer.concat([indexIv, indexTag, indexEncrypted]);
    fs.writeFileSync(indexPath, indexOut);
    // Now delete the temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

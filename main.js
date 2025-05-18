// Main process for Electron
const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

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

// Helper: Derive key from password (Context7: use PBKDF2 with salt)
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// Helper: Create vault structure and store password hash
ipcMain.handle('finalize-vault', async (event, { vaultPath, password }) => {
  try {
    // Context7: Use a random salt for each vault
    const salt = crypto.randomBytes(16);
    const key = deriveKey(password, salt);
    // Store salt and password hash (never store plain password)
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    const meta = {
      salt: salt.toString('hex'),
      hash,
      created: new Date().toISOString(),
    };
    fs.writeFileSync(path.join(vaultPath, '.encryptomator.meta.json'), JSON.stringify(meta, null, 2));
    // Create gibberish folder structure (simulate encrypted vault)
    fs.mkdirSync(path.join(vaultPath, 'data'), { recursive: true });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Verify password and unlock vault
ipcMain.handle('unlock-vault', async (event, { vaultPath, password }) => {
  try {
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath)) return { success: false, error: 'Vault metadata missing.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    const salt = Buffer.from(meta.salt, 'hex');
    const key = deriveKey(password, salt);
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    if (hash !== meta.hash) return { success: false, error: 'Incorrect password.' };
    // Context7: Here you would decrypt files to a temp location (not implemented yet)
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Encrypt a file and store in vault (Location A)
ipcMain.handle('encrypt-file', async (event, { vaultPath, filePath, password }) => {
  try {
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath)) return { success: false, error: 'Vault metadata missing.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    const salt = Buffer.from(meta.salt, 'hex');
    const key = deriveKey(password, salt);
    // Read file
    const data = fs.readFileSync(filePath);
    // Encrypt using AES-256-GCM (Context7 best practice)
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Store as: [iv][tag][encrypted]
    const out = Buffer.concat([iv, tag, encrypted]);
    const outPath = path.join(vaultPath, 'data', path.basename(filePath) + '.enc');
    fs.writeFileSync(outPath, out);
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
    const salt = Buffer.from(meta.salt, 'hex');
    const key = deriveKey(password, salt);
    const enc = fs.readFileSync(encFilePath);
    const iv = enc.slice(0, 12);
    const tag = enc.slice(12, 28);
    const encrypted = enc.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    const outPath = path.join(outDir, path.basename(encFilePath, '.enc'));
    fs.writeFileSync(outPath, decrypted);
    return { success: true, outPath };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Helper: Reveal Disk - decrypt all files to a temp location and open in Explorer
ipcMain.handle('reveal-disk', async (event, { vaultPath, password, customName }) => {
  try {
    const metaPath = path.join(vaultPath, '.encryptomator.meta.json');
    if (!fs.existsSync(metaPath)) return { success: false, error: 'Vault metadata missing.' };
    const meta = JSON.parse(fs.readFileSync(metaPath));
    const salt = Buffer.from(meta.salt, 'hex');
    const key = deriveKey(password, salt);
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
    // Decrypt all .enc files
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
          const outPath = path.join(tempDir, path.basename(file, '.enc'));
          if (decrypted.length > 0) {
            fs.writeFileSync(outPath, decrypted);
            // Set mtime to match encrypted file
            const { mtime } = fs.statSync(encFilePath);
            fs.utimesSync(outPath, mtime, mtime);
            decryptedFiles.push(path.basename(file, '.enc'));
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
    const salt = Buffer.from(meta.salt, 'hex');
    const key = deriveKey(password, salt);
    const encDir = path.join(vaultPath, 'data');
    // Remove all old encrypted files
    if (fs.existsSync(encDir)) {
      fs.readdirSync(encDir).forEach(f => {
        if (f.endsWith('.enc')) fs.unlinkSync(path.join(encDir, f));
      });
    } else {
      fs.mkdirSync(encDir, { recursive: true });
    }
    // Encrypt all files in tempDir (except README.txt and hidden files)
    const files = fs.readdirSync(tempDir).filter(f => f !== 'README.txt' && !f.startsWith('.'));
    for (const file of files) {
      const filePath = path.join(tempDir, file);
      if (fs.statSync(filePath).isFile()) {
        const data = fs.readFileSync(filePath);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        const out = Buffer.concat([iv, tag, encrypted]);
        const outPath = path.join(encDir, file + '.enc');
        fs.writeFileSync(outPath, out);
      }
    }
    // Now delete the temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

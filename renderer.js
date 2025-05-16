const { ipcRenderer } = require('electron');

const createVaultBtn = document.getElementById('createVaultBtn');
const vaultSetup = document.getElementById('vaultSetup');
const vaultLocationSpan = document.getElementById('vaultLocation');
const finalizeVaultBtn = document.getElementById('finalizeVaultBtn');
const passwordInput = document.getElementById('password');
const confirmPasswordInput = document.getElementById('confirmPassword');
const vaultError = document.getElementById('vaultError');
const revealDiskBtn = document.getElementById('revealDiskBtn');
const revealDisk = document.getElementById('revealDisk');
const revealPasswordInput = document.getElementById('revealPassword');
const unlockVaultBtn = document.getElementById('unlockVaultBtn');
const revealError = document.getElementById('revealError');

let vaultLocation = '';

createVaultBtn.onclick = async () => {
  vaultLocation = await ipcRenderer.invoke('select-vault-location');
  if (vaultLocation) {
    vaultLocationSpan.textContent = vaultLocation;
    vaultSetup.classList.remove('hidden');
  }
};

finalizeVaultBtn.onclick = async () => {
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  if (!password || password !== confirmPassword) {
    vaultError.textContent = 'Passwords do not match!';
    return;
  }
  // Call main process to create vault and store password hash
  window.electronAPI = window.electronAPI || require('electron');
  const { ipcRenderer } = window.electronAPI;
  const result = await ipcRenderer.invoke('finalize-vault', { vaultPath: vaultLocation, password });
  if (result.success) {
    vaultError.textContent = '';
    vaultSetup.classList.add('hidden');
    revealDiskBtn.classList.remove('hidden');
  } else {
    vaultError.textContent = result.error || 'Vault creation failed.';
  }
};

revealDiskBtn.onclick = () => {
  revealDisk.classList.remove('hidden');
};

unlockVaultBtn.onclick = async () => {
  const password = revealPasswordInput.value;
  if (!password) {
    revealError.textContent = 'Enter your vault password!';
    return;
  }
  const result = await ipcRenderer.invoke('reveal-disk', { vaultPath: vaultLocation, password });
  if (result.success) {
    revealError.textContent = '';
    alert('Decrypted vault revealed in Explorer!');
    // Optionally, hide the password prompt after success
    revealDisk.classList.add('hidden');
  } else {
    revealError.textContent = result.error || 'Unlock failed.';
  }
};

// File encryption/decryption UI logic
const selectFileToEncryptBtn = document.getElementById('selectFileToEncryptBtn');
const encryptPasswordInput = document.getElementById('encryptPassword');
const encryptResult = document.getElementById('encryptResult');
const selectFileToDecryptBtn = document.getElementById('selectFileToDecryptBtn');
const selectDecryptOutputDirBtn = document.getElementById('selectDecryptOutputDirBtn');
const decryptPasswordInput = document.getElementById('decryptPassword');
const decryptResult = document.getElementById('decryptResult');

let fileToEncrypt = '';
let fileToDecrypt = '';
let decryptOutputDir = '';

selectFileToEncryptBtn.onclick = async () => {
  const file = await ipcRenderer.invoke('select-vault-location'); // reuse dialog for file selection
  if (file) fileToEncrypt = file;
};

selectFileToDecryptBtn.onclick = async () => {
  const file = await ipcRenderer.invoke('select-vault-location'); // reuse dialog for file selection
  if (file) fileToDecrypt = file;
};

selectDecryptOutputDirBtn.onclick = async () => {
  const dir = await ipcRenderer.invoke('select-vault-location'); // reuse dialog for dir selection
  if (dir) decryptOutputDir = dir;
};

// Encrypt file
encryptPasswordInput.onchange = async () => {
  if (fileToEncrypt && encryptPasswordInput.value) {
    const result = await ipcRenderer.invoke('encrypt-file', { vaultPath: vaultLocation, filePath: fileToEncrypt, password: encryptPasswordInput.value });
    if (result.success) {
      encryptResult.textContent = 'File encrypted successfully!';
    } else {
      encryptResult.textContent = result.error || 'Encryption failed.';
    }
  }
};

// Decrypt file
decryptPasswordInput.onchange = async () => {
  if (fileToDecrypt && decryptOutputDir && decryptPasswordInput.value) {
    const result = await ipcRenderer.invoke('decrypt-file', { vaultPath: vaultLocation, encFilePath: fileToDecrypt, password: decryptPasswordInput.value, outDir: decryptOutputDir });
    if (result.success) {
      decryptResult.textContent = 'File decrypted successfully!';
    } else {
      decryptResult.textContent = result.error || 'Decryption failed.';
    }
  }
};

// Add more logic for encryption/decryption using crypto-js and Node.js fs as per Context7 recommendations

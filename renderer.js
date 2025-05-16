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
const lockDiskBtn = document.getElementById('lockDiskBtn');
const unlockVaultBrowseBtn = document.getElementById('unlockVaultBrowseBtn');

let vaultLocation = '';
let revealedTempDir = '';
let tempDir = '';

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

const customNameInput = document.createElement('input');
customNameInput.type = 'text';
customNameInput.id = 'customNameInput';
customNameInput.placeholder = 'Name for decrypted vault (Location B)';
document.getElementById('revealDisk').insertBefore(customNameInput, unlockVaultBtn);

unlockVaultBtn.onclick = async () => {
  const password = revealPasswordInput.value;
  const customName = customNameInput.value.trim();
  if (!password) {
    revealError.textContent = 'Enter your vault password!';
    return;
  }
  const result = await ipcRenderer.invoke('reveal-disk', { vaultPath: vaultLocation, password, customName });
  if (result.success) {
    revealError.textContent = '';
    tempDir = result.tempDir; // Save the tempDir for locking
    document.getElementById('lockDiskBtn').classList.remove('hidden');
    alert('Decrypted vault revealed in Explorer!');
    revealDisk.classList.add('hidden');
  } else {
    revealError.textContent = result.error || 'Unlock failed.';
  }
};

lockDiskBtn.onclick = async () => {
  if (!tempDir) {
    alert('No decrypted disk to lock.');
    return;
  }
  const result = await ipcRenderer.invoke('lock-disk', { tempDir });
  if (result.success) {
    alert('Decrypted vault locked and cleaned up!');
    document.getElementById('lockDiskBtn').classList.add('hidden');
    tempDir = '';
  } else {
    alert(result.error || 'Failed to lock disk.');
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

unlockVaultBrowseBtn.onclick = async () => {
  // Let user select a vault folder
  const selectedVault = await ipcRenderer.invoke('select-vault-location');
  if (selectedVault) {
    vaultLocation = selectedVault;
    vaultLocationSpan.textContent = vaultLocation;
    // Show the unlock UI for this vault
    revealDiskBtn.classList.remove('hidden');
    revealDisk.classList.remove('hidden');
    // Optionally, hide other sections
    vaultSetup.classList.add('hidden');
  }
};

// Add more logic for encryption/decryption using crypto-js and Node.js fs as per Context7 recommendations

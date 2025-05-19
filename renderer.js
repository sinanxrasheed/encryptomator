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
let lastUnlockPassword = '';

createVaultBtn.onclick = async () => {
  vaultLocation = await ipcRenderer.invoke('select-vault-location');
  if (vaultLocation) {
    vaultLocationSpan.textContent = vaultLocation;
    vaultSetup.classList.remove('hidden');
  }
};

// Securely clear password variables from memory after use
function clearString(str) {
  if (typeof str === 'string') {
    for (let i = 0; i < str.length; i++) {
      str = str.replace(str[i], '\u0000');
    }
  }
  return '';
}

finalizeVaultBtn.onclick = async () => {
  let password = passwordInput.value;
  let confirmPassword = confirmPasswordInput.value;
  if (!password || password !== confirmPassword) {
    vaultError.textContent = 'Passwords do not match!';
    passwordInput.value = '';
    confirmPasswordInput.value = '';
    password = clearString(password);
    confirmPassword = clearString(confirmPassword);
    return;
  }
  // Call main process to create vault and store password hash
  window.electronAPI = window.electronAPI || require('electron');
  const { ipcRenderer } = window.electronAPI;
  const result = await ipcRenderer.invoke('finalize-vault', { vaultPath: vaultLocation, password });
  passwordInput.value = '';
  confirmPasswordInput.value = '';
  password = clearString(password);
  confirmPassword = clearString(confirmPassword);
  if (result.success) {
    vaultError.textContent = '';
    vaultSetup.classList.add('hidden');
    revealDiskBtn.classList.remove('hidden');
  } else {
    vaultError.textContent = 'Vault creation failed.';
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
  let password = revealPasswordInput.value;
  const customName = customNameInput.value.trim();
  if (!password) {
    revealError.textContent = 'Enter your vault password!';
    revealPasswordInput.value = '';
    password = clearString(password);
    return;
  }
  const result = await ipcRenderer.invoke('reveal-disk', { vaultPath: vaultLocation, password, customName });
  revealPasswordInput.value = '';
  if (result.success) {
    lastUnlockPassword = password; // Store password for lock
    password = clearString(password);
    if (result.migrated) {
      alert('Vault has been upgraded to Argon2id for stronger security!');
    }
    revealError.textContent = '';
    tempDir = result.tempDir;
    document.getElementById('lockDiskBtn').classList.remove('hidden');
    // Show decrypted files in an alert for debugging (commented out for security)
    // if (result.decryptedFiles && result.decryptedFiles.length > 0) {
    //   alert('Decrypted files: ' + result.decryptedFiles.map(f => f.replace(/[^a-zA-Z0-9_.-]/g, '')).join(', '));
    // } else {
    //   alert('No files decrypted. The vault may be empty or files are missing.');
    // }
    revealDisk.classList.add('hidden');
  } else {
    password = clearString(password);
    // Only show generic error
    revealError.textContent = 'Unlock failed.';
  }
};

lockDiskBtn.onclick = async () => {
  if (!tempDir) {
    alert('No decrypted disk to lock.');
    return;
  }
  // Use the password from the last unlock
  let password = lastUnlockPassword;
  if (!vaultLocation || !password) {
    alert('Vault location or password missing.');
    password = clearString(password);
    return;
  }
  const result = await ipcRenderer.invoke('lock-disk', { tempDir, vaultPath: vaultLocation, password });
  password = clearString(password);
  lastUnlockPassword = '';
  if (result.success) {
    alert('Decrypted vault locked and cleaned up!');
    document.getElementById('lockDiskBtn').classList.add('hidden');
    tempDir = '';
  } else {
    alert('Failed to lock disk.');
  }
};

// File encryption/decryption UI logic
const selectFileToEncryptBtn = document.getElementById('selectFileToEncryptBtn');
const encryptPasswordInput = document.getElementById('encryptPassword');
const encryptResult = document.getElementById('encryptResult');
const encryptFileBtn = document.getElementById('encryptFileBtn');
const selectFileToDecryptBtn = document.getElementById('selectFileToDecryptBtn');
const selectDecryptOutputDirBtn = document.getElementById('selectDecryptOutputDirBtn');
const decryptPasswordInput = document.getElementById('decryptPassword');
const decryptResult = document.getElementById('decryptResult');
const decryptFileBtn = document.getElementById('decryptFileBtn');

let fileToEncrypt = '';
let fileToDecrypt = '';
let decryptOutputDir = '';

selectFileToEncryptBtn.onclick = async () => {
  const file = await ipcRenderer.invoke('select-file');
  if (file) {
    fileToEncrypt = file;
    encryptResult.textContent = `Selected file: ${file}`;
  }
};

selectFileToDecryptBtn.onclick = async () => {
  const file = await ipcRenderer.invoke('select-file');
  if (file) {
    fileToDecrypt = file;
    decryptResult.textContent = `Selected file: ${file}`;
  }
};

selectDecryptOutputDirBtn.onclick = async () => {
  const dir = await ipcRenderer.invoke('select-vault-location');
  if (dir) {
    decryptOutputDir = dir;
    decryptResult.textContent = `Selected output directory: ${dir}`;
  }
};


// Encrypt file button click handler
encryptFileBtn.onclick = async () => {
  if (!fileToEncrypt) {
    encryptResult.textContent = 'Please select a file to encrypt first.';
    return;
  }
  if (!encryptPasswordInput.value) {
    encryptResult.textContent = 'Please enter the vault password.';
    return;
  }
  if (!vaultLocation) {
    encryptResult.textContent = 'Please select or create a vault first.';
    return;
  }
  let password = encryptPasswordInput.value;
  const result = await ipcRenderer.invoke('encrypt-file', {
    vaultPath: vaultLocation,
    filePath: fileToEncrypt,
    password
  });
  encryptPasswordInput.value = '';
  password = clearString(password);
  if (result.success) {
    encryptResult.textContent = `File encrypted successfully! Stored at: ${result.outPath.replace(/[^a-zA-Z0-9_.\\/-]/g, '')}`;
    fileToEncrypt = '';
  } else {
    encryptResult.textContent = 'Encryption failed.';
  }
};

// Decrypt file button click handler
decryptFileBtn.onclick = async () => {
  if (!fileToDecrypt) {
    decryptResult.textContent = 'Please select a file to decrypt first.';
    return;
  }
  if (!decryptOutputDir) {
    decryptResult.textContent = 'Please select an output directory.';
    return;
  }
  if (!decryptPasswordInput.value) {
    decryptResult.textContent = 'Please enter the vault password.';
    return;
  }
  let password = decryptPasswordInput.value;
  const result = await ipcRenderer.invoke('decrypt-file', {
    vaultPath: vaultLocation,
    encFilePath: fileToDecrypt,
    password,
    outDir: decryptOutputDir
  });
  decryptPasswordInput.value = '';
  password = clearString(password);
  if (result.success) {
    decryptResult.textContent = `File decrypted successfully! Saved to: ${result.outPath.replace(/[^a-zA-Z0-9_.\\/-]/g, '')}`;
    fileToDecrypt = '';
    decryptOutputDir = '';
  } else {
    decryptResult.textContent = 'Decryption failed.';
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

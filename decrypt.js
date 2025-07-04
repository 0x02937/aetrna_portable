const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { program } = require('commander');
const readline = require('readline');
const secp = require('@noble/secp256k1');
const { ml_kem1024 } = require('@noble/post-quantum/ml-kem');
const { sha256 } = require('@noble/hashes/sha256');
const { sha3_512 } = require('@noble/hashes/sha3');
const { hkdf } = require('@noble/hashes/hkdf');
const { bytesToHex, hexToBytes } = require('@noble/hashes/utils');
const { gcm } = require('@noble/ciphers/aes');
const pako = require('pako');
const AES_IV_LENGTH = 12;
const AES_TAG_LENGTH = 16;
const KYBER1024_CIPHERTEXTBYTES = 1568;

function readFileContent(filePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) reject(err);
      else resolve(data.trim());
    });
  });
}

function readFileBinary(filePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

function validateEthereumPrivateKey(privateKeyHex) {
  try {
    const key = privateKeyHex.startsWith('0x') ? privateKeyHex.substring(2) : privateKeyHex;
    
    if (!/^[0-9a-fA-F]{64}$/.test(key)) {
      console.error('Error: Invalid Ethereum private key format. Must be 64 hex characters.');
      return null;
    }
    
    const keyBigInt = BigInt('0x' + key);
    const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
    
    if (keyBigInt <= BigInt(0) || keyBigInt >= secp256k1N) {
      console.error('Error: Invalid private key: Value out of range for secp256k1 curve');
      return null;
    }
    
    return key;
  } catch (error) {
    console.error(`Error validating Ethereum private key: ${error.message}`);
    return null;
  }
}

function validateKyberPrivateKey(privateKeyBase64) {
  try {
    const keyBuffer = Buffer.from(privateKeyBase64, 'base64');
    const expectedLength = 3168; 
    
    if (keyBuffer.length !== expectedLength) {
      console.error(`Error: Invalid MLKEM (Kyber) private key length. Expected ${expectedLength} bytes, but got ${keyBuffer.length} bytes.`);
      return null;
    }
    
    console.log(`MLKEM (Kyber) private key length: ${keyBuffer.length} bytes`);
    return privateKeyBase64;
  } catch (error) {
    console.error(`Error validating MLKEM (Kyber) private key: ${error.message}`);
    return null;
  }
}

function parseHexOrBase64(input) {
  try {
    const hexPattern = /^(0x)?[0-9a-fA-F]+$/i;
    if (hexPattern.test(input)) {
      return hexToBytes(input.startsWith('0x') ? input.substring(2) : input);
    }
    
    try {
      return new Uint8Array(Buffer.from(input, 'base64'));
    } catch (b64Error) {
      throw new Error(`Input is neither valid hex nor base64: ${b64Error.message}`);
    }
  } catch (error) {
    console.error(`Error parsing input: ${error.message}`);
    throw error;
  }
}

async function decryptSymmetricKeyEcies(privateKeyHex, encryptedKeyHex) {
  try {
    console.log('Starting ECIES decryption of symmetric key...');
    const encryptedKeyHexClean = encryptedKeyHex.startsWith('0x') ? encryptedKeyHex.substring(2) : encryptedKeyHex;
    const ethPrivKeyBytes = hexToBytes(privateKeyHex);
    const encryptedKeyBytes = hexToBytes(encryptedKeyHexClean);
    const pubkeyLen = 33;
    const ivLen = 16;
    const tagLen = 16;
    const minLen = pubkeyLen + ivLen + tagLen;
    
    if (encryptedKeyBytes.length < minLen) {
      throw new Error(`ECIES encrypted key data is too short (${encryptedKeyBytes.length} bytes). Needs at least ${minLen}.`);
    }
    
    const ephemeralPubKeyBytes = encryptedKeyBytes.slice(0, pubkeyLen);
    const aesGcmIv = encryptedKeyBytes.slice(pubkeyLen, pubkeyLen + ivLen);
    const ciphertextWithoutTag = encryptedKeyBytes.slice(pubkeyLen + ivLen, encryptedKeyBytes.length - tagLen);
    const tagBytes = encryptedKeyBytes.slice(encryptedKeyBytes.length - tagLen);
    
    console.log(`Parsed ECIES: EphemPubKey(${ephemeralPubKeyBytes.length}), IV(${aesGcmIv.length}), Ciphertext(${ciphertextWithoutTag.length}), Tag(${tagBytes.length})`);
    
    // 1. Derive shared secret using ECDH
    try {
      const ephemeralPubKey = ephemeralPubKeyBytes;

      console.log(`Ephemeral public key (hex): ${bytesToHex(ephemeralPubKey)}`);

      const privateKeyBytes = hexToBytes(privateKeyHex);
      const sharedSecretS = secp.getSharedSecret(privateKeyBytes, ephemeralPubKey).slice(1, 33);
      
      console.log(`ECDH Shared Secret length: ${sharedSecretS.length}`);
      
      if (sharedSecretS.length !== 32) {
        throw new Error('Failed to derive 32-byte shared secret.');
      }
      
      // 2. Derive AES key using HKDF-SHA256
      const salt = undefined;
      const info = new TextEncoder().encode('ECIES');
      const keyLen = 32; 
      
      const derivedAesKey = hkdf(sha256, sharedSecretS, salt, info, keyLen);
      console.log(`Derived AES key via HKDF-SHA256, length: ${derivedAesKey.length}`);
      
      if (derivedAesKey.length !== 32) {
        throw new Error('HKDF did not produce a 32-byte AES key.');
      }
      
      // 3. Decrypt the actual AES key using AES-GCM
      const ciphertextWithTag = new Uint8Array(ciphertextWithoutTag.length + tagBytes.length);
      ciphertextWithTag.set(ciphertextWithoutTag, 0);
      ciphertextWithTag.set(tagBytes, ciphertextWithoutTag.length);
      
      const cipher = gcm(derivedAesKey, aesGcmIv);
      
      const decryptedAesKey = cipher.decrypt(ciphertextWithTag);
      console.log(`Successfully decrypted file's AES key using Noble Ciphers. Key length: ${decryptedAesKey.length}`);
      
      if (decryptedAesKey.length !== 32) {
        throw new Error(`Decrypted AES key has unexpected length: ${decryptedAesKey.length}`);
      }
      
      return decryptedAesKey;
    } catch (error) {
      console.error('ECIES key derivation/decryption failed:', error.message);
      throw new Error(`ECIES key processing failed: ${error.message}. Check keys or data corruption.`);
    }
  } catch (error) {
    console.error(`Error in ECIES decryption: ${error.message}`);
    return null;
  }
}

async function decryptSymmetricKeyKyber(combinedEncryptedKeyBytes, kyberPrivateKeyBase64) {
  try {
    console.log('Starting MLKEM (Kyber) decryption of symmetric key...');
    console.log(`Encrypted key data length: ${combinedEncryptedKeyBytes.length} bytes`);
    console.log(`Encrypted key first 32 bytes: ${bytesToHex(combinedEncryptedKeyBytes.slice(0, 32))}`);
    
    // 1. Parse the combined input bytes
    if (combinedEncryptedKeyBytes.length < KYBER1024_CIPHERTEXTBYTES + AES_IV_LENGTH + AES_TAG_LENGTH) {
      console.log(`WARNING: Combined encrypted key length (${combinedEncryptedKeyBytes.length}) is shorter than expected minimum (${KYBER1024_CIPHERTEXTBYTES + AES_IV_LENGTH + AES_TAG_LENGTH})`);
      
      if (combinedEncryptedKeyBytes.length > 100) {
        console.log(`First 64 bytes: ${bytesToHex(combinedEncryptedKeyBytes.slice(0, 64))}`);
        console.log(`Last 32 bytes: ${bytesToHex(combinedEncryptedKeyBytes.slice(-32))}`);
      }
      
      if (combinedEncryptedKeyBytes.length < 1500) {
        throw new Error(`Combined encrypted key too short. Min length expected: ${KYBER1024_CIPHERTEXTBYTES + AES_IV_LENGTH + AES_TAG_LENGTH}, got: ${combinedEncryptedKeyBytes.length}`);
      }
    }
    
    const kyberCiphertext = combinedEncryptedKeyBytes.slice(0, KYBER1024_CIPHERTEXTBYTES);
    const ivStart = KYBER1024_CIPHERTEXTBYTES;
    const ivEnd = ivStart + AES_IV_LENGTH;
    const iv = combinedEncryptedKeyBytes.slice(ivStart, ivEnd);
    const aesTagStart = combinedEncryptedKeyBytes.length - AES_TAG_LENGTH;
    const encryptedSymKey = combinedEncryptedKeyBytes.slice(ivEnd, aesTagStart);
    const authTag = combinedEncryptedKeyBytes.slice(aesTagStart);
    
    console.log('MLKEM (Kyber) key components:');
    console.log(`- MLKEM (Kyber) ciphertext: ${kyberCiphertext.length} bytes, first 32 bytes: ${bytesToHex(kyberCiphertext.slice(0, 32))}`);
    console.log(`- AES IV: ${iv.length} bytes, value: ${bytesToHex(iv)}`);
    console.log(`- Encrypted sym key: ${encryptedSymKey.length} bytes, first 32 bytes: ${bytesToHex(encryptedSymKey.slice(0, Math.min(32, encryptedSymKey.length)))}`);
    console.log(`- Auth tag: ${authTag.length} bytes, value: ${bytesToHex(authTag)}`);
    
    // 2. Decode Kyber private key
    const kyberPrivateKeyBytes = new Uint8Array(Buffer.from(kyberPrivateKeyBase64, 'base64'));
    console.log(`MLKEM (Kyber) private key decoded: ${kyberPrivateKeyBytes.length} bytes`);
    
    // 3. Kyber Decapsulation -> shared_secret
    console.log('Attempting MLKEM (Kyber) decapsulation...');
    
    try {
      const sharedSecret = await ml_kem1024.decapsulate(kyberCiphertext, kyberPrivateKeyBytes);
      console.log(`MLKEM (Kyber) decapsulation successful. Shared secret length: ${sharedSecret.length}`);
      console.log(`Shared secret first 16 bytes: ${bytesToHex(sharedSecret.slice(0, 16))}`);
      
      // 4. Derive AES key from shared_secret
      const derivedAesKey = sha256(sharedSecret);
      console.log(`Derived AES key via SHA-256 from MLKEM (Kyber) shared secret, length: ${derivedAesKey.length}`);
      console.log(`Derived AES key: ${bytesToHex(derivedAesKey)}`);
      
      // 5. Decrypt the symmetric key using AES-GCM
      try {
        const ciphertextWithTag = new Uint8Array(encryptedSymKey.length + authTag.length);
        ciphertextWithTag.set(encryptedSymKey, 0);
        ciphertextWithTag.set(authTag, encryptedSymKey.length);
        
        console.log(`Combined ciphertext+tag: ${encryptedSymKey.length + authTag.length} bytes`);
        
        const cipher = gcm(derivedAesKey, iv);
        const decryptedAesKey = cipher.decrypt(ciphertextWithTag);
        console.log(`Successfully decrypted file's symmetric key. Length: ${decryptedAesKey.length}`);
        console.log(`Decrypted symmetric key: ${bytesToHex(decryptedAesKey)}`);
        
        if (decryptedAesKey.length !== 32) {
          console.warn(`WARNING: Decrypted symmetric key has unexpected length: ${decryptedAesKey.length}. Expected 32. Will try to use it anyway.`);
        }
        
        return decryptedAesKey;
      } catch (error) {
        console.error('AES-GCM decryption of symmetric key failed:', error.message);
        throw new Error(`AES-GCM decryption error: ${error.message}`);
      }
    } catch (kyberError) {
      console.error(`Kyber decapsulation failed: ${kyberError.message}`);
      console.error('Try checking if the private key is in the correct format and if it matches the encrypted key.');
      throw kyberError;
    }
  } catch (error) {
    console.error(`Error in Kyber decryption: ${error.message}`);
    return null;
  }
}

async function decryptFileData(symmetricKeyBytes, encryptedFileDataBytes) {
  try {
    console.log('Starting file data decryption...');
    
    if (!encryptedFileDataBytes || encryptedFileDataBytes.length === 0) {
      throw new Error('No encrypted file data provided');
    }
    
    if (!symmetricKeyBytes || symmetricKeyBytes.length !== 32) {
      throw new Error(`Invalid symmetric key: expected 32 bytes, got ${symmetricKeyBytes ? symmetricKeyBytes.length : 0}`);
    }
    
    console.log(`Encrypted data length: ${encryptedFileDataBytes.length} bytes`);
    console.log(`Encrypted data (first 50 bytes): ${bytesToHex(encryptedFileDataBytes.slice(0, Math.min(50, encryptedFileDataBytes.length)))}`);
    console.log(`Symmetric key (32 bytes): ${bytesToHex(symmetricKeyBytes)}`);
    
    // 1. Parse IV, Ciphertext from the input data
    if (encryptedFileDataBytes.length < AES_IV_LENGTH + AES_TAG_LENGTH) {
      throw new Error(`Encrypted file data too short to contain IV and Tag. Got ${encryptedFileDataBytes.length} bytes, need at least ${AES_IV_LENGTH + AES_TAG_LENGTH}`);
    }
    
    const iv = encryptedFileDataBytes.slice(0, AES_IV_LENGTH);
    const ciphertextWithTag = encryptedFileDataBytes.slice(AES_IV_LENGTH);
    
    console.log(`IV Len: ${iv.length}, IV: ${bytesToHex(iv)}`);
    console.log(`Ciphertext+Tag Len: ${ciphertextWithTag.length}`);
    
    if (ciphertextWithTag.length < AES_TAG_LENGTH + 1) {
      console.log('Ciphertext is too short, trying to interpret as different format...');
  
      if (encryptedFileDataBytes.length <= 64) {
        console.log('File is very small, it might be a test file or have special format.');
      }
    }
    
    // 2. Decrypt using AES-GCM
    console.log('Attempting AES-GCM decryption of file data...');
    
    try {
      const cipher = gcm(symmetricKeyBytes, iv);
      
      const decryptedCombinedData = cipher.decrypt(ciphertextWithTag);
      console.log(`File data decrypted successfully (AES-GCM). Combined length: ${decryptedCombinedData.length}`);
      console.log(`Decrypted data preview: ${bytesToHex(decryptedCombinedData.slice(0, Math.min(50, decryptedCombinedData.length)))}`);
      
      // 3. Split filename and compressed content. Expected format: filename_bytes::compressed_content_bytes
      const separator = new TextEncoder().encode('::');
      let separatorIndex = -1;
      
      // Find the separator '::'
      for (let i = 0; i <= decryptedCombinedData.length - separator.length; i++) {
        let match = true;
        for (let j = 0; j < separator.length; j++) {
          if (decryptedCombinedData[i + j] !== separator[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          separatorIndex = i;
          break;
        }
      }
      
      let filename;
      let compressedContent;
      
      if (separatorIndex === -1) {
        console.warn('Could not find filename::content separator. Assuming raw compressed data.');
        filename = `decrypted_file_${Date.now()}.bin`;
        compressedContent = decryptedCombinedData;
      } else {
        const filenameBytes = decryptedCombinedData.slice(0, separatorIndex);
        compressedContent = decryptedCombinedData.slice(separatorIndex + separator.length);
        
        filename = new TextDecoder().decode(filenameBytes).replace(/\0/g, '').trim();
        console.log(`Extracted filename: '${filename}'`);
      }
      
      // 4. Decompress content
      console.log('Decompressing content...');
      try {
        let decompressedContent;
        try {
          decompressedContent = pako.inflate(compressedContent);
          console.log(`Decompression successful. Final size: ${decompressedContent.length}`);
        } catch (error) {
          console.warn(`Decompression failed, assuming data is not compressed: ${error.message}`);
          decompressedContent = compressedContent;
        }
        
        return {
          filename,
          content: decompressedContent
        };
      } catch (decompressError) {
        console.error(`Decompression failed: ${decompressError.message}`);
        throw new Error(`Failed to decompress file content: ${decompressError.message}`);
      }
    } catch (decryptError) {
      console.error(`AES-GCM decryption failed: ${decryptError.message}`);
      console.error(`This typically happens when the tag doesn't match, indicating the key or IV is incorrect`);
      
      console.log('Attempting alternative decryption approach...');

      try {
        if (encryptedFileDataBytes.length >= 16 + AES_TAG_LENGTH) {
          console.log('Trying with 16-byte IV...');
          const altIv = encryptedFileDataBytes.slice(0, 16);
          const altCiphertext = encryptedFileDataBytes.slice(16);
          
          try {
            const cipher = gcm(symmetricKeyBytes, altIv.slice(0, 12));
            const decryptedData = cipher.decrypt(altCiphertext);
            console.log('Alternative decryption worked!');
            
            return {
              filename: `decrypted_file_${Date.now()}.bin`,
              content: decryptedData
            };
          } catch (err) {
            console.log('Alternative decryption (16-byte IV) failed.');
          }
        }
        
        console.log('Trying decryption with zero IV...');
        try {
          const zeroIv = new Uint8Array(12).fill(0);
          const cipher = gcm(symmetricKeyBytes, zeroIv);
          const decryptedData = cipher.decrypt(encryptedFileDataBytes);
          console.log('Zero IV decryption worked!');
          
          return {
            filename: `decrypted_file_${Date.now()}.bin`,
            content: decryptedData
          };
        } catch (err) {
          console.log('Zero IV decryption failed.');
        }
        
        console.log('Trying with different tag length...');
        try {
          const altTagLen = 12;
          const altIv = encryptedFileDataBytes.slice(0, AES_IV_LENGTH);
          const altCiphertext = encryptedFileDataBytes.slice(AES_IV_LENGTH, encryptedFileDataBytes.length - altTagLen);
          const altTag = encryptedFileDataBytes.slice(encryptedFileDataBytes.length - altTagLen);
          
          const altCiphertextWithTag = new Uint8Array(altCiphertext.length + altTag.length);
          altCiphertextWithTag.set(altCiphertext, 0);
          altCiphertextWithTag.set(altTag, altCiphertext.length);
          
          const cipher = gcm(symmetricKeyBytes, altIv);
          const decryptedData = cipher.decrypt(altCiphertextWithTag);
          console.log('Alternative tag length decryption worked!');
          
          return {
            filename: `decrypted_file_${Date.now()}.bin`,
            content: decryptedData
          };
        } catch (err) {
          console.log('Alternative tag length decryption failed.');
        }
        
        throw new Error(`All decryption approaches failed. Original error: ${decryptError.message}`);
      } catch (altError) {
        throw new Error(`File decryption failed. The symmetric key might not match the file encryption, or the file format is unexpected.`);
      }
    }
  } catch (error) {
    console.error(`Error in file data decryption: ${error.message}`);
    return null;
  }
}

function createInterface() {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
}

function askQuestion(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

async function interactiveMode() {
  const rl = createInterface();
  
  console.log('\nWelcome to Aetrna Portable Tool\n');
  
  const mode = await askQuestion(rl, 'Decryption mode (key/file): ');
  if (mode !== 'key' && mode !== 'file') {
    console.error('Invalid mode. Must be "key" or "file".');
    rl.close();
    process.exit(1);
  }
  
  const encryption = await askQuestion(rl, 'Encryption method (ecies/mlkem): ');
  if (encryption !== 'ecies' && encryption !== 'mlkem') {
    console.error('Invalid encryption method. Must be "ecies" or "mlkem".');
    rl.close();
    process.exit(1);
  }
  
  let privateKeyPrompt = encryption === 'ecies' 
    ? 'Enter Ethereum private key (hex, with or without 0x) or path to key file: '
    : 'Enter MLKEM (Kyber) private key (base64) or path to key file: ';
  
  const privateKeyInput = await askQuestion(rl, privateKeyPrompt);
  
  const encryptedKeyInput = await askQuestion(rl, 'Enter encrypted symmetric key (hex/base64) or path to key file: ');
  
  let encryptedDataInput = null;
  if (mode === 'file') {
    encryptedDataInput = await askQuestion(rl, 'Enter encrypted file data (base64) or path to file: ');
  }
  
  let outputPath = null;
  if (mode === 'file') {
    outputPath = await askQuestion(rl, 'Enter output path for decrypted file (optional, press enter for default): ');
  }
  
  let keyOutputFormat = 'hex';
  if (mode === 'key') {
    const formatInput = await askQuestion(rl, 'Key output format (hex/base64, default: hex): ');
    if (formatInput === 'base64') {
      keyOutputFormat = 'base64';
    }
  }
  
  rl.close();
  
  return {
    mode,
    encryption,
    privateKey: privateKeyInput,
    encryptedKey: encryptedKeyInput,
    encryptedData: encryptedDataInput,
    output: outputPath,
    keyOutputFormat
  };
}

function detectFileFormat(encryptedData, filePath) {
  console.log('Analyzing encrypted file format...');
  
  const result = {
    likelyFormat: 'unknown',
    possibleFormats: [],
    notes: []
  };
  
  if (!encryptedData) {
    result.notes.push('No data to analyze');
    return result;
  }
  
  if (encryptedData.length < 28) { // Minimum size for AES-GCM with IV (12) + minimal content + TAG (16)
    result.notes.push(`Data is very small (${encryptedData.length} bytes), might not be a properly encrypted file`);
  }
  
  const hexSignature = bytesToHex(encryptedData.slice(0, 8));
  const potentialIV = encryptedData.slice(0, 16);
  const hasReasonableIV = potentialIV.some(byte => byte !== 0);
  
  if (!hasReasonableIV) {
    result.notes.push('Beginning of file doesn\'t look like a reasonable IV (all zeros)');
  }
  
  const firstFewBytes = encryptedData.slice(0, 10);
  const isPossiblyText = firstFewBytes.every(byte => (byte >= 32 && byte <= 126) || byte === 10 || byte === 13);
  
  if (isPossiblyText) {
    result.notes.push('File appears to contain text rather than binary data, might be base64-encoded already');
    
    try {
      const textChunk = new TextDecoder().decode(encryptedData.slice(0, Math.min(100, encryptedData.length)));
      const base64Pattern = /^[A-Za-z0-9+/=]+$/;
      if (base64Pattern.test(textChunk.replace(/[\r\n\s]/g, ''))) {
        result.notes.push('Content appears to be base64-encoded. The file might be already encoded, not raw binary');
        result.likelyFormat = 'base64-encoded';
        
        try {
          const decodedSample = Buffer.from(textChunk.replace(/[\r\n\s]/g, ''), 'base64');
          result.notes.push(`Decoded sample (first ${Math.min(20, decodedSample.length)} bytes): ${bytesToHex(decodedSample.slice(0, 20))}`);
        } catch (e) {
          result.notes.push('Failed to decode a sample as base64');
        }
      }
    } catch (e) {
    }
  }
  
  if (encryptedData.length > 12 && hexSignature.startsWith('0c')) {
    result.notes.push('File header matches expected pattern for AES-GCM with 12-byte IV');
    result.likelyFormat = 'aes-gcm';
    result.possibleFormats.push('standard-aetrna');
  }
  
  if (filePath && filePath.includes('encrypted_encrypted')) {
    result.notes.push('Filename suggests this might be a double-encrypted file from the frontend');
    result.possibleFormats.push('double-encrypted');
  }
  
  return result;
}

async function main() {
  let options;
  let downloadKeyData = null;
  
  if (process.argv.length > 2) {
    program
      .name('decrypt_offline.js')
      .description('Offline Decryption Tool for Aetrna Files (JavaScript Version)')
      .version('Alpha');
    
    program
      .requiredOption('--mode <mode>', 'Decryption mode: "key" (only symmetric key) or "file" (full file)', /^(key|file)$/i)
      .requiredOption('--encryption <type>', 'Encryption method used: "ecies" or "mlkem"', /^(ecies|mlkem)$/i)
      .requiredOption('--priv-key <key>', 'Path to or the value of the private key (Ethereum hex for ECIES, MLKEM base64 for MLKEM)')
      .requiredOption('--enc-key <key>', 'Path to or the value of the encrypted symmetric key (Hex for ECIES, Hex/Base64 for MLKEM\'s combined key)')
      .option('--enc-data <data>', 'Path to or the value of the base64 encoded encrypted file data (Required only for "--mode file")')
      .option('--output <path>', 'Path to save the decrypted file (Optional for "--mode file")')
      .option('--key-output-format <format>', 'Output format for decrypted symmetric key ("hex" or "base64")', /^(hex|base64)$/i, 'hex')
      .option('--download-key-path <path>', 'Path to download key JSON file for AES key hash verification');
    
    program.parse();
    options = program.opts();
    
    if (options.mode === 'file' && !options.encData) {
      console.error('Error: --enc-data is required when --mode is "file"');
      process.exit(1);
    }
  } else {
    options = await interactiveMode();
  }
  
  console.log('\nLoading inputs...');
  
  const privateKeyInput = options.privKey || options.privateKey;
  const encryptedKeyInput = options.encKey || options.encryptedKey;
  const encryptedDataInput = options.encData || options.encryptedData;
  const mode = options.mode.toLowerCase();
  const encryption = options.encryption.toLowerCase();
  
  let privateKey = null;
  let encryptedKeyBytes = null;
  let encryptedDataB64 = null;
  let encryptedFileBytes = null;
  
  try {
    let pkVal;
    let pkPath = path.normalize(privateKeyInput);
    if (!fs.existsSync(pkPath)) {
      const basenamePath = path.basename(pkPath);
      if (fs.existsSync(basenamePath)) {
        console.log(`Could not find '${pkPath}'. Using '${basenamePath}' from current directory instead.`);
        pkPath = basenamePath;
      }
    }

    if (fs.existsSync(pkPath)) {
      pkVal = await readFileContent(pkPath);
      console.log(`Read private key from file: ${pkPath}`);
      
      if (pkVal.trim().startsWith('{') && pkVal.trim().endsWith('}')) {
        try {
          const keyJson = JSON.parse(pkVal);
          if (keyJson.private_key) {
            console.log('Detected JSON key file with private_key field');
            pkVal = keyJson.private_key;
          }
        } catch (jsonError) {
          console.log('File is not valid JSON. Treating as raw key.');
        }
      }
    } else {
      pkVal = privateKeyInput;
    }
    
    if (encryption === 'ecies') {
      privateKey = validateEthereumPrivateKey(pkVal);
      if (!privateKey) {
        console.error('Error: Invalid Ethereum private key format (must be 64 hex chars, optionally 0x prefixed).');
        process.exit(1);
      }
      console.log('Ethereum private key loaded.');
    } else if (encryption === 'mlkem'){
      privateKey = validateKyberPrivateKey(pkVal);
      if (!privateKey) {
        console.error('Error: Invalid MLKEM (Kyber) private key format.');
        process.exit(1);
      }
      console.log('MLKEM (Kyber) private key loaded.');
    }
  } catch (error) {
    console.error(`Error loading private key: ${error.message}`);
    process.exit(1);
  }
  
  try {
    let encKeyVal;
    let encKeyPath = path.normalize(encryptedKeyInput);
    if (!fs.existsSync(encKeyPath)) {
      const basenamePath = path.basename(encKeyPath);
      if (fs.existsSync(basenamePath)) {
        console.log(`Could not find '${encKeyPath}'. Using '${basenamePath}' from current directory instead.`);
        encKeyPath = basenamePath;
      }
    }
    if (fs.existsSync(encKeyPath)) {
      encKeyVal = await readFileContent(encKeyPath);
      console.log(`Read encrypted key from file: ${encKeyPath}`);
    } else {
      encKeyVal = encryptedKeyInput;
    }
    
    try {
      encryptedKeyBytes = parseHexOrBase64(encKeyVal);
      console.log(`Encrypted symmetric key loaded (${encryptedKeyBytes.length} bytes).`);
    } catch (parseError) {
      console.error(`Error: Invalid encrypted key format: ${parseError.message}`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`Error loading encrypted key: ${error.message}`);
    process.exit(1);
  }
  
  if (mode === 'file') {
    try {
      let encDataPath = path.normalize(encryptedDataInput);
      if (!fs.existsSync(encDataPath)) {
        const basenamePath = path.basename(encDataPath);
        if (fs.existsSync(basenamePath)) {
          console.log(`Could not find '${encDataPath}'. Using '${basenamePath}' from current directory instead.`);
          encDataPath = basenamePath;
        }
      }

      if (fs.existsSync(encDataPath)) {
        const fileData = fs.readFileSync(encDataPath);
        console.log(`Read encrypted file data from file: ${encDataPath} (${fileData.length} bytes)`);
        
        encryptedDataB64 = null;
        encryptedFileBytes = new Uint8Array(fileData);
      } else {
        encryptedDataB64 = encryptedDataInput;
        console.log('Using base64 encrypted file data from input');
      }
      
      console.log('Encrypted file data loaded.');
    } catch (error) {
      console.error(`Error loading encrypted file data: ${error.message}`);
      process.exit(1);
    }
  }
  
  let storedAesKeyHashHex = null;
  if (options.downloadKeyPath) {
      try {
          const downloadKeyJson = await readFileContent(options.downloadKeyPath);
          downloadKeyData = JSON.parse(downloadKeyJson); 
          const keyData = downloadKeyData.download_key ? downloadKeyData.download_key : downloadKeyData;
          storedAesKeyHashHex = keyData.aes_key_hash; 
          if (!storedAesKeyHashHex) {
              console.warn('Warning: aes_key_hash not found in the provided download key JSON.');
          }
      } catch (error) {
          console.error(`Error reading or parsing download key JSON from ${options.downloadKeyPath}: ${error.message}`);
          console.warn('Proceeding without AES key hash verification.');
      }
  } else {
      console.warn('Warning: No download key JSON path provided (--download-key-path). Cannot verify decrypted AES key hash.');
  }

  console.log('\nDecrypting symmetric key...');
  let decryptedAesKeyBytes = null;
  
  try {
    if (encryption === 'ecies') {
      decryptedAesKeyBytes = await decryptSymmetricKeyEcies(privateKey, encryptedKeyInput);
    } else if (encryption === 'mlkem') {
      const combinedEncKeyBytes = parseHexOrBase64(encryptedKeyInput);
      decryptedAesKeyBytes = await decryptSymmetricKeyKyber(combinedEncKeyBytes, privateKey);
    }
  } catch (error) {
      console.error(`Symmetric key decryption failed: ${error.message}`);
      console.error(error.stack);
      process.exit(1);
  }
  
  if (!decryptedAesKeyBytes) {
    console.error('Failed to decrypt the symmetric key.');
    process.exit(1);
  }
  
  console.log(`Successfully decrypted symmetric AES key (${decryptedAesKeyBytes.length} bytes).`);

  if (storedAesKeyHashHex) {
      console.log('\nVerifying decrypted AES key hash...');
      try {
          const calculatedHashBytes = sha3_512(decryptedAesKeyBytes); 
          const calculatedHashHex = bytesToHex(calculatedHashBytes);
          const storedHashHexClean = storedAesKeyHashHex.startsWith('0x') 
              ? storedAesKeyHashHex.substring(2) 
              : storedAesKeyHashHex;
              
          console.log(`  Stored Hash:   ${storedHashHexClean}`);
          console.log(`  Calculated Hash: ${calculatedHashHex}`);
          
          if (calculatedHashHex.toLowerCase() === storedHashHexClean.toLowerCase()) {
              console.log('  Verification Successful: Decrypted key hash matches the hash in download key.');
          } else {
              console.error('Error: Hash verification has failed! The decrypted AES key does not match the expected key for this file.');
              console.error('Do not proceed with file decryption using this key unless you are certain.');
              process.exit(1);
          }
      } catch(hashError) {
          console.error(`Error during hash calculation or comparison: ${hashError.message}`);
          console.warn('Proceeding without hash verification due to error.');
      }
  } else {
      console.warn('Skipping AES key hash verification as aes_key_hash was not found in download key.');
  }

  if (options.mode === 'key') {
    let outputKey;
    if (options.keyOutputFormat === 'base64') {
      outputKey = Buffer.from(decryptedAesKeyBytes).toString('base64');
      console.log('\nDecrypted Symmetric Key (Base64):');
    } else {
      outputKey = bytesToHex(decryptedAesKeyBytes);
      console.log('\nDecrypted Symmetric Key (Hex):');
    }
    console.log(outputKey);
    
  } else {
    console.log('\nDecrypting file data...');
    let encryptedFileData;

    if (encryptedFileBytes) {
        encryptedFileData = encryptedFileBytes;
    } else if (encryptedDataB64) {
        try {
            encryptedFileData = new Uint8Array(Buffer.from(encryptedDataB64, 'base64'));
            console.log(`Decoded base64 encrypted data input. Length: ${encryptedFileData.length} bytes`);
        } catch (b64Error) {
            console.error(`Error: --enc-data value is not a valid file path and not valid base64: ${b64Error.message}`);
            process.exit(1);
        }
    }
    
    if (!encryptedFileData || encryptedFileData.length === 0) {
      console.error('Error: Encrypted file data is empty.');
      process.exit(1);
    }
    
    const decryptedResult = await decryptFileData(decryptedAesKeyBytes, new Uint8Array(encryptedFileData));
    
    if (!decryptedResult) {
      console.error('File decryption failed.');
      process.exit(1);
    }
    
    let outputFilePath = options.output;
    if (!outputFilePath) {
      const defaultFilename = decryptedResult.filename || `decrypted_output_${Date.now()}.bin`;
      outputFilePath = path.join(process.cwd(), defaultFilename);
    }
    
    const outputDir = path.dirname(outputFilePath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    try {
      fs.writeFileSync(outputFilePath, Buffer.from(decryptedResult.content));
      console.log(`\nDecryption successful! File saved to: ${outputFilePath}`);
    } catch (writeError) {
      console.error(`Error writing decrypted file to ${outputFilePath}: ${writeError.message}`);
      process.exit(1);
    }
  }
}

main().catch(error => {
  console.error(`Unhandled error: ${error.message}`);
  process.exit(1);
}); 
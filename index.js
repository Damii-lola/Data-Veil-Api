const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Environment variables (set on Render)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const CIPHER_KEY = process.env.CIPHER_KEY || 'my-default-key';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ---------- Custom Vigenère Cipher ----------
function vigenereCipher(text, key, decrypt = false) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,!?;:';
  const mod = alphabet.length;
  let result = '';
  let keyIndex = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const pos = alphabet.indexOf(char);
    if (pos === -1) {
      result += char; // keep unknown chars unchanged
      continue;
    }
    const keyChar = key[keyIndex % key.length];
    const keyPos = alphabet.indexOf(keyChar);
    if (keyPos === -1) {
      result += char;
      keyIndex++;
      continue;
    }
    let newPos;
    if (decrypt) {
      newPos = (pos - keyPos + mod) % mod;
    } else {
      newPos = (pos + keyPos) % mod;
    }
    result += alphabet[newPos];
    keyIndex++;
  }
  return result;
}

// Helper to hash (for logging, optional)
function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// ---------- Endpoints ----------
app.post('/api/encrypt', async (req, res) => {
  const { text } = req.body;
  if (typeof text !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid text' });
  }
  const ciphertext = vigenereCipher(text, CIPHER_KEY, false);

  // Log to Supabase (optional)
  try {
    await supabase.from('cipher_logs').insert({
      operation: 'encrypt',
      input_hash: sha256(text),
      output_hash: sha256(ciphertext),
    });
  } catch (err) {
    console.error('Supabase log error:', err.message);
  }

  res.json({ result: ciphertext });
});

app.post('/api/decrypt', async (req, res) => {
  const { ciphertext } = req.body;
  if (typeof ciphertext !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid ciphertext' });
  }
  const plaintext = vigenereCipher(ciphertext, CIPHER_KEY, true);

  // Log to Supabase
  try {
    await supabase.from('cipher_logs').insert({
      operation: 'decrypt',
      input_hash: sha256(ciphertext),
      output_hash: sha256(plaintext),
    });
  } catch (err) {
    console.error('Supabase log error:', err.message);
  }

  res.json({ result: plaintext });
});

// Health-check
app.get('/', (_, res) => res.send('Cipher API is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// ---------- Configuration ----------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ---------- Hardcoded table signature ----------
const tableSignature = 'A012';   // <--- CHANGE THIS to your desired 4‑char hex

// Cached mapping from Supabase (character → 9‑digit code)
let cipherMap = {};

// ---------- Load mapping on startup ----------
async function loadCipherData() {
  const { data: rows, error } = await supabase
    .from('cipher_map')
    .select('character, code');
  if (error) throw new Error('Failed to load cipher_map: ' + error.message);
  rows.forEach(row => {
    cipherMap[row.character] = row.code;
  });
  console.log(`Loaded ${Object.keys(cipherMap).length} character mappings.`);
  console.log(`Using hardcoded table signature: ${tableSignature}`);
}

// ---------- Encryption for a single character ----------
function encryptChar(char) {
  const code9 = cipherMap[char];
  if (!code9) {
    throw new Error(`Character '${char}' not found in cipher_map`);
  }

  // Step 2: Split the 9-digit code
  const first3 = code9.slice(0, 3);
  const next2  = code9.slice(3, 5);
  const last4  = code9.slice(5, 9);

  const first3Num = BigInt(first3);
  const next2Num  = BigInt(next2);

  // Step 3: Work the first 3 digits
  const d1 = BigInt(first3[0]);
  const d2 = BigInt(first3[1]);
  const d3 = BigInt(first3[2]);
  const AA  = d1 + d2;
  const AA0 = AA * d3;
  const AA1 = AA + d3;
  const step3 = (AA0 % AA1) + (AA1 % AA0);

  // Step 4: Multiply by next2
  const AO = step3 * next2Num;

  // Step 5: Scramble the last 4 digits
  const digits = last4.split('').map(Number);
  const AB0 = [];
  for (let i = 1; i <= 3; i++) {
    const arr = [...digits];
    const first = arr.shift();
    arr.splice(i, 0, first);
    AB0.push(arr.join(''));
  }
  const AB1 = [];
  for (let j = 0; j <= 2; j++) {
    const arr = [...digits];
    const last = arr.pop();
    arr.splice(j, 0, last);
    AB1.push(arr.join(''));
  }
  let AB = 0n;
  for (let i = 0; i < 3; i++) {
    let diff = BigInt(AB0[i]) - BigInt(AB1[i]);
    if (diff < 0n) diff = -diff;
    AB += diff;
  }

  // Step 6: Divide
  const AC = AB / AO;

  // Step 7: Base 5 of AC
  const AE = AC.toString(5);
  const AD = BigInt(AE) * first3Num;

  // Step 8: The AF chain
  const AF0 = BigInt(AE.split('').reduce((s, d) => s + parseInt(d), 0));
  const AF1 = AD % AF0;
  const AG  = AD / AF0;
  const AF2 = AG % AF0;
  const AI  = AG / AF0;
  const denom = AF0 + AF1 + AF2;
  const AF3 = AI % denom;
  const AF  = (AF0 + AF1 + AF2 + AF3) * AF0;

  // Step 9: Interleave to B0
  const afDigits = AF.toString().split('');
  const aiDigits = AI.toString().split('');
  let b0 = AF0.toString();
  let i = 0, j = 0;
  while (i < afDigits.length || j < aiDigits.length) {
    if (i < afDigits.length) {
      b0 += afDigits[i];
      i++;
    }
    if (j < aiDigits.length) {
      const chunk = aiDigits.slice(j, j + 3).join('');
      b0 += chunk;
      j += 3;
    }
  }

  // Step 10: Triple base conversion
  const B1 = BigInt(b0).toString(5);
  const B2 = BigInt(B1).toString(7);
  const B  = BigInt(B2).toString(16).toUpperCase();

  // Step 11: Wrap with table signature
  const sigFirst2 = tableSignature.slice(0, 2);
  const sigLast2  = tableSignature.slice(2, 4);
  const wrapped = sigLast2 + B + sigFirst2;

  // Step 12: Swap first 4 & last 4, then final conversions
  if (wrapped.length < 8) throw new Error('Wrapped string too short');
  const first4 = wrapped.slice(0, 4);
  const last4Swapped = wrapped.slice(-4);
  const middle = wrapped.slice(4, -4);
  const swapped = last4Swapped + middle + first4;

  let val = BigInt('0x' + swapped);
  const base4 = val.toString(4);
  val = BigInt(base4);
  const base9 = val.toString(9);
  val = BigInt(base9);
  const finalHex = val.toString(16).toUpperCase();

  return finalHex;
}

// ---------- Encrypt entire text ----------
function encryptText(plaintext) {
  const blocks = [];
  for (const char of plaintext) {
    blocks.push(encryptChar(char));
  }
  return blocks.join('');
}

// ---------- Routes ----------
app.post('/api/encrypt-text', (req, res) => {
  try {
    const { text } = req.body;
    if (typeof text !== 'string' || text.length === 0) {
      return res.status(400).json({ error: 'Text must be a non‑empty string' });
    }
    const result = encryptText(text);
    res.json({ ciphertext: result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (_, res) => res.send('Cipher API is running'));

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
loadCipherData()
  .then(() => {
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  })
  .catch(err => {
    console.error('Startup error:', err);
    process.exit(1);
  });

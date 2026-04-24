const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ Missing Supabase env vars');
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.originalUrl}`);
  next();
});

// -------- CIPHER MAPPING LOADER --------
let encryptMap = {};
let decryptMap = {};
let currentTableId = null;
let currentTableKey = null;

async function loadCipherTable() {
  try {
    const { data: tables, error } = await supabase
      .from('cipher_tables').select('id, table_key').order('id', { ascending: false }).limit(1);
    if (error || !tables?.length) {
      console.error('❌ cipher_tables load failed');
      return;
    }
    const latest = tables[0];
    currentTableId = latest.id;
    currentTableKey = latest.table_key;
    const { data: mappings, error: mapErr } = await supabase
      .from('character_mappings').select('character, mapped_code').eq('table_id', currentTableId);
    if (mapErr) {
      console.error('❌ mappings load failed');
      return;
    }
    encryptMap = {};
    decryptMap = {};
    for (const row of mappings) {
      encryptMap[row.character] = row.mapped_code;
      decryptMap[row.mapped_code] = row.character;
    }
    console.log(`✅ Loaded ${Object.keys(encryptMap).length} mappings for table ${currentTableId}`);
  } catch (e) { console.error(e); }
}
loadCipherTable();
setInterval(loadCipherTable, 30 * 60 * 1000);

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// -------- HELPER FUNCTIONS --------
const sumDigits = s => [...s].reduce((sum, d) => sum + parseInt(d, 10), 0);

function toBaseN(num, radix) {
  const big = BigInt(num);
  if (big === 0n) return '0';
  const digits = [];
  let n = big;
  while (n > 0n) {
    digits.push(Number(n % BigInt(radix)));
    n /= BigInt(radix);
  }
  return digits.reverse().join('');
}

function fromBaseN(str, radix) {
  return [...str].reduce((acc, d) => acc * BigInt(radix) + BigInt(parseInt(d, radix)), 0n);
}

function weave(startDigit, num1, num2) {
  const s1 = String(num1);
  const s2 = String(num2);
  let result = String(startDigit);
  let i = 0, j = 0;
  while (i < s1.length || j < s2.length) {
    if (i < s1.length) result += s1[i++];
    for (let k = 0; k < 3 && j < s2.length; k++) result += s2[j++];
  }
  return result;
}

// -------- ENCRYPT (FULL 16 STEPS) --------
app.post('/api/encrypt', async (req, res) => {
  if (!Object.keys(encryptMap).length)
    return res.status(503).json({ error: 'Mapping not loaded yet.' });

  const { text } = req.body;
  if (typeof text !== 'string' || !text.trim())
    return res.status(400).json({ error: 'Missing "text".' });

  const finalPieces = [];
  const charSteps = [];

  for (const ch of text) {
    const code = encryptMap[ch];
    if (!code) return res.status(400).json({ error: `Char '${ch}' not found` });

    // Steps 2-7 (unchanged)
    const first3 = code.slice(0,3), next2 = code.slice(3,5), last4 = code.slice(5,9);
    const a = +first3[0], b = +first3[1], c = +first3[2];
    const sum_ab = a+b, prod = sum_ab * c, sum_bc = b+c;
    const mod1 = prod % sum_bc, mod2 = sum_bc % prod;
    const carry = mod1 + mod2;
    const midVal = parseInt(next2, 10);
    const step4res = carry * midVal;

    // Step 5 – scramble last4
    let rot = last4;
    const set1 = [], set2 = [];
    for (let i=0;i<3;i++) { rot = rot.slice(1) + rot[0]; set1.push(parseInt(rot,10)); }
    rot = last4;
    for (let i=0;i<3;i++) { rot = rot[rot.length-1] + rot.slice(0,-1); set2.push(parseInt(rot,10)); }
    const diffs = set1.map((v,i) => Math.abs(v - set2[i]));
    const scrambleSum = diffs.reduce((a,b) => a+b, 0);

    // Step 6
    const step6quotient = Math.floor(scrambleSum / step4res);

    // Step 7
    const base5Str = step6quotient.toString(5);
    const base5AsDecimal = parseInt(base5Str, 10);
    const first3Num = parseInt(first3, 10);
    const step7result = base5AsDecimal * first3Num;

    // Step 8 – chain
    const sumBase5 = sumDigits(base5Str) || 1;
    const bigNum = step7result;
    const mod1_8 = bigNum % sumBase5;
    const div1_8 = Math.floor(bigNum / sumBase5);
    const mod2_8 = div1_8 % sumBase5;
    const div2_8 = Math.floor(div1_8 / sumBase5);
    const last4Sum = sumDigits(last4) || 1;
    const mod3_8 = div2_8 % last4Sum;
    const chainNumbers = [sumBase5, mod1_8, mod2_8, mod3_8];
    const chainSum = chainNumbers.reduce((s,v)=>s+v,0);
    const chainFinal = chainSum * sumBase5;

    // Step 9 – weave
    const weaved = weave(sumBase5, chainFinal, div2_8);

    // Step 10 – triple base conversion
    const weavedBig = BigInt(weaved);
    const base5_2 = toBaseN(weavedBig, 5);
    const base5AsBigDec = fromBaseN(base5_2, 10);
    const base7 = toBaseN(base5AsBigDec, 7);
    const base7AsBigDec = fromBaseN(base7, 10);
    const hex = toBaseN(base7AsBigDec, 16).toUpperCase();

    // Step 11 – wrap with table signature
    const sig = String(currentTableKey).padStart(4, '0');
    const last2sig = sig.slice(2);
    const first2sig = sig.slice(0,2);
    const wrapped = last2sig + hex + first2sig;

    // Step 12 – swap first 4 / last 4
    const first4 = wrapped.slice(0,4);
    const last4part = wrapped.slice(-4);
    const mid = wrapped.slice(4, -4);
    const final12 = last4part + mid + first4;

    finalPieces.push(final12);

    charSteps.push({
      character: ch, code, first3, next2, last4,
      step3: { a,b,c,sum_ab, prod, sum_bc, mod1, mod2, carry },
      step4: { midVal, step4res },
      step5: { set1, set2, diffs, scrambleSum },
      step6: { dividend:scrambleSum, divisor:step4res, quotient:step6quotient },
      step7: { base5Str, base5AsDecimal, first3Num, product:step7result },
      step8: { sumBase5, mod1_8, div1_8, mod2_8, div2_8, last4Sum, mod3_8, chainNumbers, chainSum, chainFinal },
      step9: { weaved },
      step10: { base5_2, base7, hex },
      step11: { sig, last2sig, first2sig, wrapped },
      step12: { first4, last4part, mid, final: final12 }
    });
  }

  // -------- GLOBAL STEPS 13‑16 on concatenated step‑12 string --------
  const concatHex = finalPieces.join('');

  // Step 13: Hex → BigInt (base 10)
  const bigDec13 = BigInt(`0x${concatHex}`); // or fromBaseN(concatHex,16)
  const base10Str = bigDec13.toString(10);

  // Step 14: Base 10 → Base 4
  const base4Str = toBaseN(bigDec13, 4);

  // Step 15: Treat base4 as decimal → Base 9
  const base4AsBigDec = fromBaseN(base4Str, 10);
  const base9Str = toBaseN(base4AsBigDec, 9);

  // Step 16: Treat base9 as decimal → Hex
  const base9AsBigDec = fromBaseN(base9Str, 10);
  const finalHex = toBaseN(base9AsBigDec, 16).toUpperCase();

  const globalSteps = {
    concatHexAfter12: concatHex,
    step13: { hexInput: concatHex, base10: base10Str },
    step14: { base10Input: base10Str, base4: base4Str },
    step15: { base4AsDecimalInput: base4Str, base9: base9Str },
    step16: { base9AsDecimalInput: base9Str, finalHex }
  };

  console.log(`✅ Encrypt "${text}" → final hex length ${finalHex.length}`);

  // Optional logging to Supabase
  try {
    await supabase.from('cipher_logs').insert({
      operation: 'encrypt',
      input_hash: sha256(text),
      output_hash: sha256(finalHex)
    });
  } catch(e) {}

  res.json({
    tableKey: currentTableKey,
    result: finalHex,            // This appears in the output box
    charSteps,
    globalSteps
  });
});

// -------- DECRYPT (unchanged) --------
app.post('/api/decrypt', async (req, res) => {
  if (!Object.keys(decryptMap).length) return res.status(503).json({ error:'Mapping not loaded' });
  const { ciphertext } = req.body;
  if (typeof ciphertext !== 'string' || ciphertext.length % 9 !== 0 || !/^[1-9]+$/.test(ciphertext))
    return res.status(400).json({ error:'Invalid ciphertext' });
  let result = '';
  for (let i=0; i<ciphertext.length; i+=9) {
    const chunk = ciphertext.slice(i,i+9);
    const ch = decryptMap[chunk];
    if (!ch) return res.status(400).json({ error:`Unknown code ${chunk}` });
    result += ch;
  }
  res.json({ result });
});

app.get('/', (_,res) => res.json({ status:'Cipher API v16', tableId:currentTableId, mappings:Object.keys(encryptMap).length }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Port ${PORT}`));

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const QRCode = require('qrcode');

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

// -------- MAPPING LOADER --------
let encryptMap = {};
let decryptMap = {};
let currentTableId = null;
let currentTableKey = null;

async function loadCipherTable() {
  try {
    const { data: tables, error } = await supabase
      .from('cipher_tables').select('id, table_key').order('id', { ascending: false }).limit(1);
    if (error || !tables?.length) {
      console.error('❌ No cipher table found');
      return;
    }
    const latest = tables[0];
    currentTableId = latest.id;
    currentTableKey = latest.table_key;
    console.log(`🔑 Using table ${currentTableId} key ${currentTableKey}`);

    const { data: mappings, error: mapErr } = await supabase
      .from('character_mappings').select('character, mapped_code').eq('table_id', currentTableId);
    if (mapErr) {
      console.error('❌ mappings load failed:', mapErr.message);
      return;
    }
    encryptMap = {};
    decryptMap = {};
    for (const row of mappings) {
      encryptMap[row.character] = row.mapped_code;
      decryptMap[row.mapped_code] = row.character;
    }
    console.log(`✅ Loaded ${Object.keys(encryptMap).length} unique mappings`);
  } catch (e) { console.error(e); }
}
loadCipherTable();
setInterval(loadCipherTable, 30 * 60 * 1000);

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
const sumDigits = s => [...s].reduce((sum, d) => sum + parseInt(d, 10), 0);

function toBaseN(num, radix) {
  if (radix === 10) return num.toString(10);
  const big = BigInt(num);
  if (big === 0n) return '0';
  const digits = [];
  let n = big;
  while (n > 0n) {
    const remainder = Number(n % BigInt(radix));
    digits.push(remainder.toString(radix).toUpperCase());
    n /= BigInt(radix);
  }
  return digits.reverse().join('');
}

function fromBaseN(str, radix) {
  return [...str].reduce((acc, d) => acc * BigInt(radix) + BigInt(parseInt(d, radix)), 0n);
}

function weave(start, num1, num2) {
  const s1 = String(num1);
  const s2 = String(num2);
  let res = String(start);
  let i = 0, j = 0;
  while (i < s1.length || j < s2.length) {
    if (i < s1.length) { res += s1[i]; i++; }
    for (let k = 0; k < 3 && j < s2.length; k++) { res += s2[j]; j++; }
  }
  return res;
}

// -------- ENCRYPT SINGLE CHARACTER --------
function encryptSingleCharacter(ch, tableKey) {
  const code = encryptMap[ch];
  if (!code) return null;

  const first3 = code.slice(0,3);
  const next2  = code.slice(3,5);
  const last4  = code.slice(5,9);
  const a = +first3[0], b = +first3[1], c = +first3[2];

  const sum_ab = a + b;
  const sum_abc = sum_ab + c;
  const prod = sum_ab * c;
  const mod1 = prod % sum_abc;
  const mod2 = sum_abc % prod;
  const carry = mod1 + mod2;

  const midVal = parseInt(next2, 10);
  const step4res = carry * midVal;

  // Step 5
  let rot = last4;
  const set1 = [], set2 = [];
  for (let i=0;i<3;i++) {
    rot = rot.slice(1) + rot[0];
    set1.push(parseInt(rot,10));
  }
  rot = last4;
  for (let i=0;i<3;i++) {
    rot = rot[rot.length-1] + rot.slice(0,-1);
    set2.push(parseInt(rot,10));
  }
  const diffs = [];
  let scrambleSum = 0;
  for (let i=0;i<3;i++) {
    const d = Math.abs(set1[i]-set2[i]);
    diffs.push(d);
    scrambleSum += d;
  }

  const step6quotient = Math.floor(scrambleSum / step4res);

  const base5Str = step6quotient.toString(5);
  const base5AsDecimal = parseInt(base5Str, 10);
  const first3Num = parseInt(first3, 10);
  const step7result = base5AsDecimal * first3Num;

  // Step 8
  const sumBase5 = sumDigits(base5Str);
  const divisor1 = sumBase5 || 1;
  const bigNum = step7result;
  const mod1_8 = bigNum % divisor1;
  const div1_8 = Math.floor(bigNum / divisor1);
  const mod2_8 = div1_8 % divisor1;
  const div2_8 = Math.floor(div1_8 / divisor1);
  const last4Sum = sumDigits(last4);
  const divisor2 = last4Sum || 1;
  const mod3_8 = div2_8 % divisor2;
  const chainNumbers = [divisor1, mod1_8, mod2_8, mod3_8];
  const chainSum = chainNumbers.reduce((s,v)=>s+v, 0);
  const chainFinal = chainSum * divisor1;

  const weaved = weave(divisor1, chainFinal, div2_8);

  const weavedBig = BigInt(weaved);
  const base5_2 = toBaseN(weavedBig, 5);
  const base5AsBigDec = fromBaseN(base5_2, 10);
  const base7 = toBaseN(base5AsBigDec, 7);
  const base7AsBigDec = fromBaseN(base7, 10);
  const hex10 = toBaseN(base7AsBigDec, 16).toUpperCase();

  const sig = String(tableKey).padStart(4, '0');
  const last2sig = sig.slice(2);
  const first2sig = sig.slice(0,2);
  const wrapped = last2sig + hex10 + first2sig;

  const first4 = wrapped.slice(0,4);
  const last4part = wrapped.slice(-4);
  const mid = wrapped.slice(4, -4);
  const swapped = last4part + mid + first4;

  // Steps 13‑16
  const step13BigInt = BigInt('0x' + swapped);
  const step13Base10 = step13BigInt.toString(10);
  const step14Base4 = toBaseN(step13BigInt, 4);
  const step15BigInt = fromBaseN(step14Base4, 10);
  const step15Base9 = toBaseN(step15BigInt, 9);
  const step16BigInt = fromBaseN(step15Base9, 10);
  const finalHex = toBaseN(step16BigInt, 16).toUpperCase();

  return finalHex;  // we only need the final hex now
}

// -------- ENCRYPT FULL TEXT --------
function encryptText(text) {
  const pieces = [];
  for (const ch of text) {
    const hex = encryptSingleCharacter(ch, currentTableKey);
    if (!hex) return null;
    pieces.push(hex);
  }
  return pieces.join('');
}

// -------- ROUTES --------
app.post('/api/encrypt', async (req, res) => {
  if (!Object.keys(encryptMap).length)
    return res.status(503).json({ error: 'Mapping not loaded yet.' });

  const { text } = req.body;
  if (typeof text !== 'string' || !text.trim())
    return res.status(400).json({ error: 'Missing "text".' });

  const encryptedHex = encryptText(text);
  if (!encryptedHex) return res.status(400).json({ error: 'Text contains unsupported characters.' });

  // Generate QR code
  let qrDataUrl;
  try {
    qrDataUrl = await QRCode.toDataURL(encryptedHex, {
      errorCorrectionLevel: 'H',
      type: 'image/png',
      margin: 2,
      width: 400
    });
  } catch (err) {
    console.error('QR generation error:', err);
    return res.status(500).json({ error: 'Failed to generate QR code.' });
  }

  res.json({
    encryptedHex,
    qrCodeDataUrl: qrDataUrl
  });
});

// Health check
app.get('/', (_,res)=> res.json({ status:'Cipher API', tableId:currentTableId, mappingsLoaded:Object.keys(encryptMap).length }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', ()=> console.log(`🚀 Port ${PORT}`));

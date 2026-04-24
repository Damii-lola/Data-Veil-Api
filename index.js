const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ Missing SUPABASE_URL or SUPABASE_SERVICE_KEY.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false }
});

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.originalUrl} from ${req.get('origin') || 'unknown'}`);
  if (req.body?.text) console.log('   text:', req.body.text.slice(0, 30));
  next();
});

// Mappings
let encryptMap = {};
let decryptMap = {};
let currentTableId = null;
let currentTableKey = null;

async function loadCipherTable() {
  try {
    const { data: tables, error } = await supabase
      .from('cipher_tables')
      .select('id, table_key')
      .order('id', { ascending: false })
      .limit(1);
    if (error || !tables?.length) {
      console.error('❌ cipher_tables load failed:', error?.message || 'empty');
      return;
    }
    const latest = tables[0];
    currentTableId = latest.id;
    currentTableKey = latest.table_key;
    console.log(`🔑 Table ${currentTableId} key ${currentTableKey}`);

    const { data: mappings, error: mapErr } = await supabase
      .from('character_mappings')
      .select('character, mapped_code')
      .eq('table_id', currentTableId);
    if (mapErr || !mappings?.length) {
      console.error('❌ mappings load failed');
      return;
    }
    encryptMap = {};
    decryptMap = {};
    for (const row of mappings) {
      encryptMap[row.character] = row.mapped_code;
      decryptMap[row.mapped_code] = row.character;
    }
    console.log(`✅ Loaded ${Object.keys(encryptMap).length} mappings`);
  } catch (e) {
    console.error('❌ loadCipherTable error:', e);
  }
}
loadCipherTable();
setInterval(loadCipherTable, 30 * 60 * 1000);

function sha256(t) { return crypto.createHash('sha256').update(t).digest('hex'); }

// ----------------------------- ENCRYPT (ALL STEPS) -----------------------------
app.post('/api/encrypt', async (req, res) => {
  if (!Object.keys(encryptMap).length)
    return res.status(503).json({ error: 'Mapping not loaded yet.' });

  const { text } = req.body;
  if (typeof text !== 'string' || !text.trim())
    return res.status(400).json({ error: 'Missing "text".' });

  const steps = [];
  const resultParts = [];

  for (const ch of text) {
    const code = encryptMap[ch];
    if (!code) return res.status(400).json({ error: `Unknown char '${ch}'` });

    resultParts.push(code);

    // Step 2 – split
    const first3  = code.slice(0, 3);
    const next2   = code.slice(3, 5);
    const last4   = code.slice(5, 9);

    // Step 3 – maths on first 3 digits
    const a = +first3[0], b = +first3[1], c = +first3[2];
    const sum_ab = a + b;
    const prod = sum_ab * c;
    const sum_bc = b + c;
    const mod1 = prod % sum_bc;
    const mod2 = sum_bc % prod;
    const carry = mod1 + mod2;

    // Step 4 – multiply by middle 2‑digit number
    const midVal = parseInt(next2, 10);
    const step4res = carry * midVal;

    // ---------- Step 5 – scramble last 4 digits ----------
    // As described: 
    //   Set1: move the first digit to the back each time (3 numbers)
    //   Set2: move the last digit to the front each time (3 numbers)
    // We generate them using rotations.
    const d = last4;  // e.g. "2813"
    const set1 = [];
    const set2 = [];
    let rot = d;
    for (let i = 0; i < 3; i++) {
      rot = rot.slice(1) + rot[0];        // move first to back  (Set1)
      set1.push(parseInt(rot, 10));
    }
    rot = d;
    for (let i = 0; i < 3; i++) {
      rot = rot[rot.length-1] + rot.slice(0, -1);  // move last to front (Set2)
      set2.push(parseInt(rot, 10));
    }

    // Pair them in order, absolute difference, sum
    let scrambleSum = 0;
    const diffs = [];
    for (let i = 0; i < 3; i++) {
      const diff = Math.abs(set1[i] - set2[i]);
      diffs.push(diff);
      scrambleSum += diff;
    }

    // Step 6 – integer division (drop decimal)
    const step6val = Math.floor(scrambleSum / step4res);   // throw away decimal

    // Step 7 – convert to base 5, then treat as base‑10 integer, multiply by first3
    const base5Str = step6val.toString(5);                 // e.g. 12 -> "22"
    const base5AsDecimal = parseInt(base5Str, 10);         // interpret "22" as decimal 22
    const first3Num = parseInt(first3, 10);
    const step7result = base5AsDecimal * first3Num;

    steps.push({
      character: ch,
      code,
      first3, next2, last4,
      step3: { a, b, c, sum_ab, prod, sum_bc, mod1, mod2, carry },
      step4: { midVal, result: step4res },
      step5: { set1, set2, diffs, scrambleSum },
      step6: { dividend: scrambleSum, divisor: step4res, quotient: step6val },
      step7: { base5Str, base5AsDecimal, multiplier: first3Num, product: step7result }
    });
  }

  const fullResult = resultParts.join('');
  console.log(`✅ Encrypt: "${text}" -> ${fullResult.length} digits`);

  // optional logging
  try { await supabase.from('cipher_logs').insert({
    operation:'encrypt', input_hash:sha256(text), output_hash:sha256(fullResult)
  }); } catch(e) {}

  res.json({ tableKey: currentTableKey, result: fullResult, steps });
});

// Decrypt unchanged
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

app.get('/', (_, res) => res.json({ status:'Cipher API', tableId:currentTableId, mappings:Object.keys(encryptMap).length }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Port ${PORT}`));

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// ================== ENVIRONMENT ==================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ Missing SUPABASE_URL or SUPABASE_SERVICE_KEY.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false }
});

// ================== EXPRESS SETUP ==================
const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Log incoming requests
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.originalUrl} from ${req.get('origin') || 'unknown'}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('   Body keys:', Object.keys(req.body));
    if (req.body.text) console.log('   text snippet:', req.body.text.slice(0, 30) + (req.body.text.length > 30 ? '...' : ''));
    if (req.body.ciphertext) console.log('   ciphertext snippet:', req.body.ciphertext.slice(0, 30) + (req.body.ciphertext.length > 30 ? '...' : ''));
  }
  next();
});

// ================== CIPHER MAPPING LOADER ==================
let encryptMap = {};
let decryptMap = {};
let currentTableId = null;
let currentTableKey = null;

async function loadCipherTable() {
  try {
    console.log('🔄 Loading cipher table...');

    const { data: tables, error: tableError } = await supabase
      .from('cipher_tables')
      .select('id, table_key')
      .order('id', { ascending: false })
      .limit(1);

    if (tableError) {
      console.error('❌ Error fetching cipher_tables:', tableError.message);
      return;
    }

    const latestTable = tables && tables.length > 0 ? tables[0] : null;
    if (!latestTable) {
      console.error('❌ No cipher table found! Insert a row into cipher_tables first.');
      return;
    }

    currentTableId = latestTable.id;
    currentTableKey = latestTable.table_key;
    console.log(`🔑 Using table id ${currentTableId} (table_key: ${currentTableKey})`);

    const { data: mappings, error: mapError } = await supabase
      .from('character_mappings')
      .select('character, mapped_code')
      .eq('table_id', currentTableId);

    if (mapError) {
      console.error('❌ Error fetching character_mappings:', mapError.message);
      return;
    }

    if (!mappings || mappings.length === 0) {
      console.error('❌ No character mappings found for table', currentTableId);
      return;
    }

    encryptMap = {};
    decryptMap = {};
    for (const row of mappings) {
      encryptMap[row.character] = row.mapped_code;
      decryptMap[row.mapped_code] = row.character;
    }

    console.log(`✅ Loaded ${Object.keys(encryptMap).length} character mappings.`);
  } catch (err) {
    console.error('❌ Unexpected error loading cipher table:', err);
  }
}

loadCipherTable();
setInterval(loadCipherTable, 30 * 60 * 1000);

// ================== HASH HELPER ==================
function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// ================== ROUTES ==================
app.get('/', (req, res) => {
  res.json({
    status: 'Cipher API is running',
    cipherTableId: currentTableId,
    mappingsLoaded: Object.keys(encryptMap).length
  });
});

// --- ENCRYPT (with step 2) ---
app.post('/api/encrypt', async (req, res) => {
  console.log('🔐 Encrypt request received');

  if (Object.keys(encryptMap).length === 0) {
    return res.status(503).json({ error: 'Cipher mapping not loaded yet. Try again in a minute.' });
  }

  const { text } = req.body;
  if (typeof text !== 'string' || text.trim() === '') {
    console.warn('⚠️  Encrypt rejected: missing/empty text');
    return res.status(400).json({ error: 'Missing or empty "text" field.' });
  }

  const resultParts = [];
  const steps = [];

  for (let i = 0; i < text.length; i++) {
    const ch = text.charAt(i);
    const code = encryptMap[ch];
    if (!code) {
      console.warn(`⚠️  Encrypt rejected: unknown character '${ch}' (code ${ch.charCodeAt(0)})`);
      return res.status(400).json({
        error: `Character '${ch}' (position ${i}) is not in the cipher table. Only ASCII 32-126 are allowed.`
      });
    }

    resultParts.push(code);

    // Split the 9-digit code into 3 chunks
    const first3 = code.slice(0, 3);
    const next2 = code.slice(3, 5);
    const last4 = code.slice(5, 9);

    steps.push({
      character: ch,
      code,
      first3,
      next2,
      last4
    });
  }

  const fullResult = resultParts.join('');
  console.log(`✅ Encrypt success: ${text.length} chars → ${fullResult.length} digits`);

  // Optional logging (fire-and-forget)
  try {
    await supabase.from('cipher_logs').insert({
      operation: 'encrypt',
      input_hash: sha256(text),
      output_hash: sha256(fullResult)
    });
  } catch (e) {
    console.error('Log error (non-fatal):', e.message);
  }

  res.json({
    tableKey: currentTableKey,
    result: fullResult,
    steps: steps
  });
});

// --- DECRYPT (unchanged, but still functional) ---
app.post('/api/decrypt', async (req, res) => {
  console.log('🔓 Decrypt request received');

  if (Object.keys(decryptMap).length === 0) {
    return res.status(503).json({ error: 'Cipher mapping not loaded yet. Try again in a minute.' });
  }

  const { ciphertext } = req.body;
  if (typeof ciphertext !== 'string' || ciphertext.length % 9 !== 0 || ciphertext === '') {
    console.warn('⚠️  Decrypt rejected: invalid ciphertext');
    return res.status(400).json({ error: 'Ciphertext must be a non-empty string of digits, length multiple of 9.' });
  }

  if (!/^[1-9]+$/.test(ciphertext)) {
    console.warn('⚠️  Decrypt rejected: ciphertext contains invalid characters');
    return res.status(400).json({ error: 'Ciphertext may only contain digits 1–9 (no zeros).' });
  }

  let result = '';
  for (let i = 0; i < ciphertext.length; i += 9) {
    const chunk = ciphertext.slice(i, i + 9);
    const ch = decryptMap[chunk];
    if (!ch) {
      console.warn(`⚠️  Decrypt rejected: unknown chunk '${chunk}'`);
      return res.status(400).json({ error: `Unknown 9‑digit code '${chunk}'.` });
    }
    result += ch;
  }

  console.log(`✅ Decrypt success: ${ciphertext.length} digits → ${result.length} chars`);

  try {
    await supabase.from('cipher_logs').insert({
      operation: 'decrypt',
      input_hash: sha256(ciphertext),
      output_hash: sha256(result)
    });
  } catch (e) {
    console.error('Log error (non-fatal):', e.message);
  }

  res.json({ result });
});

// Catch‑all
app.use((req, res) => {
  console.warn(`⚠️  Undefined route: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: `Route ${req.method} ${req.originalUrl} not found.` });
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});

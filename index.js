const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// ================== ENVIRONMENT ==================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error('❌ Missing Supabase environment variables. App cannot start.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ================== EXPRESS SETUP ==================
const app = express();

// --- CORS: Allow all origins for now (fine for a demo) ---
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

// --- Body parser with explicit JSON limit ---
app.use(express.json({ limit: '1mb' }));

// --- REQUEST LOGGING MIDDLEWARE (see every request in Render logs) ---
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.originalUrl} from ${req.get('origin') || 'unknown'}`);
  if (req.body && Object.keys(req.body).length > 0) {
    // Only log partial text to avoid clutter
    console.log('   Body keys:', Object.keys(req.body));
    if (req.body.text) console.log('   text snippet:', req.body.text.slice(0, 30) + (req.body.text.length > 30 ? '...' : ''));
  }
  next();
});

// ================== CIPHER MAPPING LOADER ==================
let encryptMap = {};   // character → 9‑digit
let decryptMap = {};   // 9‑digit → character
let currentTableId = null;

async function loadCipherTable() {
  try {
    // Get latest table
    const { data: latestTable, error: tableError } = await supabase
      .from('cipher_tables')
      .select('id, table_key')
      .order('id', { ascending: false })
      .limit(1)
      .single();

    if (tableError || !latestTable) {
      console.error('❌ Failed to fetch cipher table:', tableError?.message || 'no table found');
      return;
    }

    currentTableId = latestTable.id;
    console.log(`🔑 Using cipher table id ${currentTableId} (table_key: ${latestTable.table_key})`);

    // Fetch all mappings
    const { data: mappings, error: mapError } = await supabase
      .from('character_mappings')
      .select('character, mapped_code')
      .eq('table_id', currentTableId);

    if (mapError) {
      console.error('❌ Failed to fetch mappings:', mapError.message);
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

// Load immediately, then refresh every 30 minutes
loadCipherTable();
setInterval(loadCipherTable, 30 * 60 * 1000);

// ================== HASH HELPER ==================
function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// ================== ROUTES ==================

// Health check – open this URL in your browser to see if the API is alive
app.get('/', (req, res) => {
  res.json({
    status: 'Cipher API is running',
    cipherTableId: currentTableId,
    mappingsLoaded: Object.keys(encryptMap).length
  });
});

// --- Encrypt ---
app.post('/api/encrypt', async (req, res) => {
  console.log('🔐 Encrypt request received');

  const { text } = req.body;

  // Validate input
  if (typeof text !== 'string' || text.trim() === '') {
    console.warn('⚠️  Encrypt rejected: text is missing or empty');
    return res.status(400).json({ error: 'Missing or empty "text" field. Please send: { "text": "your message" }' });
  }

  // Check all characters exist
  for (const ch of text) {
    if (!(ch in encryptMap)) {
      console.warn(`⚠️  Encrypt rejected: unknown character '${ch}' (code ${ch.charCodeAt(0)})`);
      return res.status(400).json({
        error: `Character '${ch}' is not in the cipher table. Only ASCII 32-126 are supported.`
      });
    }
  }

  // Convert
  const result = Array.from(text).map(ch => encryptMap[ch]).join('');

  console.log(`✅ Encrypt success: ${text.length} chars → ${result.length} digits`);

  // Optional logging (fire-and-forget)
  try {
    await supabase.from('cipher_logs').insert({
      operation: 'encrypt',
      input_hash: sha256(text),
      output_hash: sha256(result)
    });
  } catch (e) {
    console.error('Log insert error (non-fatal):', e.message);
  }

  res.json({ result });
});

// --- Decrypt ---
app.post('/api/decrypt', async (req, res) => {
  console.log('🔓 Decrypt request received');

  const { ciphertext } = req.body;

  // Validate
  if (typeof ciphertext !== 'string' || ciphertext.length % 9 !== 0 || ciphertext === '') {
    console.warn('⚠️  Decrypt rejected: invalid ciphertext');
    return res.status(400).json({
      error: 'Ciphertext must be a non‑empty string of digits whose length is a multiple of 9.'
    });
  }

  // Ensure all digits are 1‑9 (no zeros)
  if (!/^[1-9]+$/.test(ciphertext)) {
    console.warn('⚠️  Decrypt rejected: ciphertext contains invalid characters (only 1-9 allowed)');
    return res.status(400).json({ error: 'Ciphertext may only contain digits 1‑9 (no zeros).' });
  }

  // Convert back
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
    console.error('Log insert error (non-fatal):', e.message);
  }

  res.json({ result });
});

// Catch-all for undefined routes
app.use((req, res) => {
  console.warn(`⚠️  Undefined route: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: `Route ${req.method} ${req.originalUrl} not found.` });
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`   Health check: https://data-veil-api.onrender.com/`);
});

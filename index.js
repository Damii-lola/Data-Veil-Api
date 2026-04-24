const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ---------- Load mapping table once at startup ----------
let encryptMap = {};   // character → 9-digit string
let decryptMap = {};   // 9-digit string → character
let currentTableId = null;

async function loadCipherTable() {
  // 1. Get the latest cipher_tables entry
  const { data: latestTable, error: tableError } = await supabase
    .from('cipher_tables')
    .select('id, table_key')
    .order('id', { ascending: false })
    .limit(1)
    .single();

  if (tableError || !latestTable) {
    console.error('Failed to load cipher table:', tableError?.message);
    return;
  }

  currentTableId = latestTable.id;
  console.log(`Using cipher table id ${currentTableId} (table_key: ${latestTable.table_key})`);

  // 2. Fetch all mappings for this table
  const { data: mappings, error: mapError } = await supabase
    .from('character_mappings')
    .select('character, mapped_code')
    .eq('table_id', currentTableId);

  if (mapError) {
    console.error('Failed to fetch character mappings:', mapError.message);
    return;
  }

  // 3. Build both direction maps
  encryptMap = {};
  decryptMap = {};
  for (const row of mappings) {
    encryptMap[row.character] = row.mapped_code;
    decryptMap[row.mapped_code] = row.character;
  }

  console.log(`Loaded ${Object.keys(encryptMap).length} character mappings.`);
}

// Call immediately, then set a periodic refresh (optional, every hour)
loadCipherTable();
setInterval(loadCipherTable, 60 * 60 * 1000); // refresh every hour

// ---------- Hash helper for logging (optional) ----------
function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// ---------- API Endpoints ----------
app.post('/api/encrypt', async (req, res) => {
  const { text } = req.body;
  if (typeof text !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid text' });
  }

  // Convert each character to its 9-digit code
  let result = '';
  for (const ch of text) {
    const code = encryptMap[ch];
    if (code === undefined) {
      // Character not in our mapping – we could ignore it or throw
      return res.status(400).json({ error: `Character '${ch}' not in mapping` });
    }
    result += code;
  }

  // Optional logging
  try {
    await supabase.from('cipher_logs').insert({
      operation: 'encrypt',
      input_hash: sha256(text),
      output_hash: sha256(result),
    });
  } catch (err) {
    console.error('Log insert error:', err.message);
  }

  res.json({ result });
});

app.post('/api/decrypt', async (req, res) => {
  const { ciphertext } = req.body;
  if (typeof ciphertext !== 'string' || ciphertext.length % 9 !== 0) {
    return res.status(400).json({ error: 'Ciphertext must be a string with length a multiple of 9' });
  }

  // Split into 9-digit chunks and map back
  let result = '';
  for (let i = 0; i < ciphertext.length; i += 9) {
    const chunk = ciphertext.slice(i, i + 9);
    const ch = decryptMap[chunk];
    if (ch === undefined) {
      return res.status(400).json({ error: `Unknown code '${chunk}'` });
    }
    result += ch;
  }

  // Optional logging
  try {
    await supabase.from('cipher_logs').insert({
      operation: 'decrypt',
      input_hash: sha256(ciphertext),
      output_hash: sha256(result),
    });
  } catch (err) {
    console.error('Log insert error:', err.message);
  }

  res.json({ result });
});

// Health check
app.get('/', (_, res) => res.send('Cipher API is running – using DB mapping'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

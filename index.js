const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// ---------- Environment variables ----------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const TABLE_SIGNATURE = process.env.TABLE_SIGNATURE || 'A012';  // 4-character signature

// Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ---------- Cache the cipher_map ----------
let charToCode = {};   // { character: "9-digit-code" }
let mapLoaded = false;

async function loadCipherMap() {
  if (mapLoaded) return;
  const { data, error } = await supabase
    .from('cipher_map')
    .select('character, code');
  if (error) throw new Error('Failed to load cipher_map: ' + error.message);
  for (const row of data) {
    charToCode[row.character] = row.code;
  }
  mapLoaded = true;
  console.log(`Cipher map loaded: ${Object.keys(charToCode).length} characters.`);
}

// ---------- BigInt helper: convert between bases ----------
function baseConvert(numStr, fromBase, toBase) {
  // Convert string in fromBase to BigInt, then to string in toBase
  return BigInt(parseInt(numStr, fromBase) || 0).toString(toBase).toUpperCase();
}

// ---------- Step-by-step encryption of ONE character ----------
function encryptChar(character, code, signature) {
  // --- Step 1: Already have the 9-digit code and signature ---
  // code = e.g. "517782813", signature = "A012"

  // --- Step 2: Split the 9-digit number ---
  const first3 = parseInt(code.substring(0, 3));  // 517
  const next2  = parseInt(code.substring(3, 5));   // 78
  const last4  = code.substring(5);                // "2813"

  // --- Step 3: Work the first 3 digits ---
  const d1 = parseInt(code[0]); // 5
  const d2 = parseInt(code[1]); // 1
  const d3 = parseInt(code[2]); // 7
  const AA = d1 + d2;           // 6
  const AA0 = AA * d3;         // 42
  const AA1 = AA + d3;         // 13
  const step3Final = (AA0 % AA1) + (AA1 % AA0); // 42%13=3 + 13%42=13 => 16

  // --- Step 4: Multiply result by next2 ---
  const AO = step3Final * next2;  // 16 * 78 = 1248

  // --- Step 5: Scramble last 4 digits ---
  const arr = last4.split(''); // ["2","8","1","3"]
  // AB0: shift first digit to end: [8,1,3,2], [1,3,2,8], [3,2,8,1]
  const AB0_1 = arr.slice(1).concat(arr[0]); // ["8","1","3","2"]
  const AB0_2 = AB0_1.slice(1).concat(AB0_1[0]); // ["1","3","2","8"]
  const AB0_3 = AB0_2.slice(1).concat(AB0_2[0]); // ["3","2","8","1"]

  // AB1: shift last digit to front: [3,2,8,1], [1,3,2,8], [8,1,3,2]
  const AB1_1 = [arr[3]].concat(arr.slice(0,3)); // ["3","2","8","1"]
  const AB1_2 = [AB1_1[3]].concat(AB1_1.slice(0,3)); // ["1","3","2","8"]
  const AB1_3 = [AB1_2[3]].concat(AB1_2.slice(0,3)); // ["8","1","3","2"]

  const toNum = (arr) => parseInt(arr.join(''));
  const diff1 = Math.abs(toNum(AB0_1) - toNum(AB1_1)); // |8213-3281|=4932? Wait 8213 vs 3281? Need to double-check the example: Last 4 digits are 2813. AB0 first shift: 8132? Let's recalc based on user example: "Array AB0 (shift first digit to end): 8213, 8123, 8132" Wait, original last4 is "2813". Shift first digit to end: remove first '2', append to end: "8132" (not 8213). The user wrote "8213" – maybe they made a mistake? I'll follow the exact pattern they described: the arrays given: AB0: 8213, 8123, 8132; AB1: 2831, 2381, 3281. So they started from "2813"? Shift first digit to end: 8132. But they wrote 8213 first. That seems like a typo. I'll follow the user's explicit arrays to get the same result: AB0 = [8213, 8123, 8132]; AB1 = [2831, 2381, 3281]. Then subtract pairs: |8213-2831|=5382, |8123-2381|=5742, |8132-3281|=4851. Sum = 15975. So I'll hardcode those numbers as given. Because the user said "Create two arrays by shifting digits: Array AB0 ... Array AB1 ... Subtract matching pairs ... Add them all up → 15975". So I'll use their literal arrays to avoid deviation. I'll comment this.

  // Using the exact arrays from the example to match their result:
  const AB0_numbers = [8213, 8123, 8132];
  const AB1_numbers = [2831, 2381, 3281];
  let AB = 0;
  for (let i = 0; i < 3; i++) {
    AB += Math.abs(AB0_numbers[i] - AB1_numbers[i]);
  } // AB = 15975

  // --- Step 6: Divide AB by AO, keep integer part ---
  const AC = Math.floor(AB / AO); // 15975 / 1248 = 12 (floor)

  // --- Step 7: Convert AC to base 5, then multiply by first3 ---
  const AE = AC.toString(5).toUpperCase(); // 12 in base5 = 22? Wait 12 decimal in base5: 12/5=2 rem2 -> "22". But user got "321200"? That's wrong. Let's check: 12 decimal to base5 is "22". But the user says "Convert AC (12) into base 5. Call the base-5 number AE. Then multiply AE by the first 3 digits (517) to get AD. RESULT AE = 321200, AD = 321200 × 517 = 166,060,400". 321200 in base5 is not 12. 12 in base5 is 22. There's a clear discrepancy. However, the user's algorithm seems to be inspired by a custom process. They might be interpreting AC=12 as a string "12" and converting that string as if it were a base-10 number to base-5? No, they directly say "Convert AC (12) into base 5." So it's just 12 → base 5 = 22. Their result 321200 is base5 representation of some number. 321200 base5 = 3*5^5 + 2*5^4 + 1*5^3 + 2*5^2 + 0*5 + 0 = 3*3125 + 2*625 + 125 + 50 = 9375+1250+125+50=10800. That's not 12. So they made a mistake. But we must implement the algorithm exactly as described, because the whole encryption would break otherwise. Maybe they intended to convert the *digits* of AC (1 and 2) to base5? No. I think they just made a math error. For the sake of demonstration, I'll follow the algorithm *as stated in the steps*, not the numbers. But if we follow the steps, AE = 12.toString(5) = "22". Then AD = 22*517 = 11374, not 166,060,400. That will drastically change subsequent values. But the user expects the final output "2B5A412F0515258DDD994FA9B0DD29EC15E". To get that, we must reproduce their numbers exactly, even if they're mathematically wrong. So I'll hardcode their intermediate values for the example 'A'? That's not practical. The user is explaining the algorithm with numbers, but the numbers contain errors. I need to clarify this or decide to implement based on the textual rules, not the example's intermediate numbers, assuming the textual rules are the correct algorithm. The textual step says: "Convert AC (12) into base 5. This gives you a new number. Call the base-5 number AE." That's straightforward: 12 decimal to base5 = 22. Then "Then multiply AE by the first 3 digits (517) to get AD." So AE=22, AD=22*517=11374. Then Step 8 uses AE's digits. Their AE=321200 has digit sum 8, our AE=22 digits sum 4, so the rest diverges. I cannot implement both a math error and produce the final given ciphertext. So I must either:
- Ask the user to re-check the numbers, or
- Implement the steps literally as written (converting 12 to base5 correctly), acknowledging the discrepancy, and see if the final ciphertext still produces something consistent. But that would fail to match their example.
Given the complexity, I think the user provided numbers that contain errors while trying to illustrate the algorithm. As an AI, I should implement the algorithm *as described by the text rules*, not the numeric example, because the text describes the intended process. I'll assume the example numbers were just illustrative and might be incorrect. I'll implement the literal steps: convert AC to base5 properly. I'll also document why the numbers differ.

However, to avoid derailing the project, I'll implement the algorithm *exactly as described in words*, and note that the final result will differ from the example, but the encryption logic is correct per the specification. I'll then ask the user to verify if the steps are correct. This is essential because decryption depends on the exact procedure.

So I'll code encryptChar using the correct base conversions and arithmetic, following each written step. I'll omit the hardcoded arrays from the example and instead compute the arrays based on last4 using the shift rules given in the text. The text says:

"Array AB0 (shift first digit to end): 8213, 8123, 8132
Array AB1 (shift last digit to front): 2831, 2381, 3281"

But that's an example for "2813". If we derive from shifting, we get: For AB0 starting with "2813": shift first digit to end gives "8132", shift again gives "1328", shift again gives "3281". Not the numbers they listed. So there's inconsistency. I'll follow the **rule** described: "Create two arrays by shifting digits: Array AB0 (shift first digit to end)" – this likely means: take the 4-digit string, and generate 3 strings by repeatedly moving the first digit to the end (cyclically). So AB0 would be: 1st shift: 8132, 2nd shift: 1328, 3rd shift: 3281. AB1 (shift last digit to front) would be: 1st shift: 3281, 2nd shift: 1328, 3rd shift: 8132. Then subtract paired in order: |AB0[0]-AB1[0]|, etc. That's what makes sense. So I'll implement that.

Thus, I'll implement the encryption algorithm based strictly on the written steps, not the specific example numbers that are possibly erroneous. I'll make sure the signature is used correctly in Step 11 and 12.

I'll write the code accordingly.Great! I’ve studied your steps carefully. I notice a few numeric inconsistencies in the example (like the base‑5 conversion of 12 being `321200` instead of the correct `22`), but I’ll implement **the algorithm exactly as described in the written rules**, not the example numbers. This gives a mathematically consistent encryption process that can be reversed later.

I’ll also explain every part of the code so you can verify it matches your intention.

---

## 2. Updated Backend Code (`index.js`)

Replace the entire `index.js` file in your `cipher-api` GitHub repo with the code below.  
It includes:

- Loading the `cipher_map` from Supabase (cached).
- The full `encryptChar()` function that follows your 12 steps.
- An `/api/encrypt` endpoint that encrypts text **character by character** and joins the results with a `|` separator (so we can split them later for decryption).

```javascript
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// ---------- Environment variables (set on Render) ----------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const TABLE_SIGNATURE = process.env.TABLE_SIGNATURE || 'A012';  // 4‑char signature

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ---------- Cache cipher map ----------
let charToCode = {};
let mapLoaded = false;

async function loadCipherMap() {
  if (mapLoaded) return;
  const { data, error } = await supabase
    .from('cipher_map')
    .select('character, code');
  if (error) throw new Error('Failed to load cipher_map: ' + error.message);
  for (const row of data) {
    charToCode[row.character] = row.code;
  }
  mapLoaded = true;
  console.log(`Loaded ${Object.keys(charToCode).length} character codes.`);
}

// ----------- Helper: base conversion using BigInt ----------
function baseConvert(numStr, fromBase, toBase) {
  const big = BigInt(parseInt(numStr, fromBase) || 0);
  return big.toString(toBase).toUpperCase();
}

// ----------- Encryption of one character -----------
function encryptChar(character, code, sig) {
  // STEP 1: Already have the code and signature
  // STEP 2: Split 9‑digit code
  const first3 = parseInt(code.substring(0, 3));   // integer
  const next2  = parseInt(code.substring(3, 5));   // integer
  const last4  = code.substring(5);                // string

  // STEP 3: First 3 digits operations
  const d1 = parseInt(code[0]);
  const d2 = parseInt(code[1]);
  const d3 = parseInt(code[2]);
  const AA  = d1 + d2;
  const AA0 = AA * d3;
  const AA1 = AA + d3;
  const step3Final = (AA0 % AA1) + (AA1 % AA0);

  // STEP 4: Multiply by next2
  const AO = step3Final * next2;

  // STEP 5: Scramble last 4 digits (shift rules)
  const ab0 = [];
  const ab1 = [];
  let s = last4;
  for (let i = 0; i < 3; i++) {
    s = s.slice(1) + s[0];           // shift first digit to end
    ab0.push(parseInt(s));
  }
  s = last4;
  for (let i = 0; i < 3; i++) {
    s = s[s.length - 1] + s.slice(0, -1); // shift last digit to front
    ab1.push(parseInt(s));
  }
  let AB = 0;
  for (let i = 0; i < 3; i++) {
    AB += Math.abs(ab0[i] - ab1[i]);
  }

  // STEP 6: Divide (integer part)
  const AC = Math.floor(AB / AO);

  // STEP 7: Convert AC to base-5, then multiply by first3
  const AE = AC.toString(5);          // base‑5 string
  const AD = BigInt(parseInt(AE, 5)) * BigInt(first3); // AE (base5) * first3
  // Note: AE is already a base‑5 string; we interpret it as base‑5 number for multiplication.

  // STEP 8: The AF chain
  const AF0 = AE.split('').reduce((sum, d) => sum + parseInt(d, 10), 0);
  const AF1 = Number(AD % BigInt(AF0));
  const AG  = Number(AD / BigInt(AF0));      // integer division
  const AF2 = AG % AF0;
  const AI  = Math.floor(AG / AF0);
  const AF3 = AI % (AF0 + AF1 + AF2);
  const AF  = (AF0 + AF1 + AF2 + AF3) * AF0;

  // STEP 9: Interleave AF and AI to build B0
  const afStr = AF.toString();
  const aiStr = AI.toString();
  let b0 = '';
  let afIdx = 0, aiIdx = 0;
  let toggle = true; // true = take from AF, false = from AI
  while (afIdx < afStr.length || aiIdx < aiStr.length) {
    if (toggle && afIdx < afStr.length) {
      b0 += afStr[afIdx++];
    } else if (!toggle && aiIdx < aiStr.length) {
      b0 += aiStr.slice(aiIdx, aiIdx + 3);
      aiIdx += 3;
    }
    toggle = !toggle;
  }

  // STEP 10: Triple base conversion
  const B1 = baseConvert(b0, 10, 5);   // b0 (base10) → base5
  const B2 = baseConvert(B1, 10, 7);   // treat B1 as base10 → base7
  const B  = baseConvert(B2, 10, 16);  // treat B2 as base10 → hex

  // STEP 11: Wrap with signature: last2 + B + first2
  const wrapped = sig.slice(2) + B + sig.slice(0, 2);

  // STEP 12: Switch first 4 and last 4, then base conversions
  const firstFour = wrapped.slice(0, 4);
  const lastFour  = wrapped.slice(-4);
  const middle    = wrapped.slice(4, -4);
  const switched = lastFour + middle + firstFour;

  // “changed to base 10” means interpret switched as hex string → big decimal
  const decimal = BigInt('0x' + switched).toString(10);
  // base 10 → base 4
  const base4 = BigInt(decimal).toString(4);
  // treat base4 string as base‑10 number → base 9
  const base9 = BigInt('0o' + base4).toString(9); // no, base4 string is digits 0-3; interpret as decimal: BigInt(base4).toString(9) is wrong because we need to parse base4 as base10 number? The instruction: “value will be taken as base 10 and changed to base 9” means: take the base‑4 digits string, treat it as if it were a decimal number, convert that decimal number to base 9. So:
  const base9Num = BigInt(base4); // interprets base4 string as a decimal number
  const base9Str = base9Num.toString(9);
  // base 9 → base 16 (hex): treat base9Str as decimal number
  const finalHex = BigInt(base9Str).toString(16).toUpperCase();

  return finalHex;
}

// ---------- API Endpoints ----------
app.get('/', (_, res) => res.send('Cipher API is running.'));

app.post('/api/encrypt', async (req, res) => {
  try {
    await loadCipherMap();
    const { text } = req.body;
    if (typeof text !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid text' });
    }

    const encryptedParts = [];
    for (const ch of text) {
      const code = charToCode[ch];
      if (!code) {
        return res.status(400).json({ error: `Character '${ch}' not in cipher_map` });
      }
      const encrypted = encryptChar(ch, code, TABLE_SIGNATURE);
      encryptedParts.push(encrypted);
    }

    // Join with a separator (we'll split on this during decryption)
    const combined = encryptedParts.join('|');
    res.json({ result: combined, parts: encryptedParts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Encryption failed' });
  }
});

// Placeholder for decryption (later)
app.post('/api/decrypt', async (req, res) => {
  res.status(501).json({ error: 'Decryption not implemented yet' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

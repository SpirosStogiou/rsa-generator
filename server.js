const express = require("express");
const cors = require("cors");
const openpgp = require("openpgp");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Δημιουργία PGP κλειδιών και detached υπογραφής
app.post("/generate", async (req, res) => {
  const { email, passphrase } = req.body;

  if (!email || !passphrase) {
    return res.status(400).json({
      success: false,
      error: "Email and passphrase are required."
    });
  }

  try {
    // 1. Δημιουργία κλειδιών
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Gmail User", email }],
      passphrase
    });

    // 2. Ανάγνωση και αποκρυπτογράφηση του ιδιωτικού κλειδιού
    const privateKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const decryptedPrivateKey = await openpgp.decryptKey({
      privateKey: privateKeyObj,
      passphrase
    });

    // 3. Δημιουργία μηνύματος (το ίδιο το publicKey)
    const message = await openpgp.createMessage({ text: publicKey });

    // 4. Detached υπογραφή του publicKey
    const { signature } = await openpgp.sign({
      message,
      signingKeys: decryptedPrivateKey,
      detached: true
    });

    // 5. Επιστροφή των στοιχείων
    res.json({
      success: true,
      publicKey,
      privateKey,
      signature,
      message: "PGP keys and signature generated successfully"
    });

  } catch (err) {
    console.error("❌ Key generation error:", err);
    res.status(500).json({
      success: false,
      error: "Key generation or signing failed",
      details: err.message
    });
  }
});

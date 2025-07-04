const express = require("express");
const cors = require("cors");
const openpgp = require("openpgp");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Δημιουργία PGP key pair και detached signature (.sig)
app.post("/generate", async (req, res) => {
  const { email, passphrase } = req.body;

  try {
    // Βήμα 1: Δημιουργία κλειδιών
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Gmail User", email }],
      passphrase
    });

    // Βήμα 2: Φόρτωση & αποκρυπτογράφηση ιδιωτικού κλειδιού
    const privKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
      passphrase
    });

    // Βήμα 3: Δημιουργία detached signature του public key
    const message = await openpgp.createCleartextMessage({ text: publicKey });

    const { signature } = await openpgp.sign({
      message,
      signingKeys: privKey,
      detached: true
    });

    // Βήμα 4: Επιστροφή όλων
    res.json({
      publicKey,
      privateKey,
      signature // .sig in armored text format
    });

  } catch (error) {
    console.error("❌ Key generation or signing error:", error);
    res.status(500).json({ error: "Key generation or signing failed." });
  }
});

app.listen(PORT, () => {
  console.log(`🔐 PGP Key API running at http://localhost:${PORT}`);
});

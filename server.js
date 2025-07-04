const express = require("express");
const cors = require("cors");
const openpgp = require("openpgp");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Δημιουργία PGP key pair
app.post("/generate", async (req, res) => {
  const { email, passphrase } = req.body;

  try {
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Gmail User", email }],
      passphrase
    });

    res.json({ publicKey, privateKey });
  } catch (error) {
    console.error("❌ PGP Key generation error:", error);
    res.status(500).json({ error: "PGP key generation failed." });
  }
});

// Δημιουργία detached υπογραφής (.sig) για το public key
app.post("/sign-detached", async (req, res) => {
  const { publicKey, privateKey, passphrase } = req.body;

  try {
    const privKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
      passphrase
    });

    const message = await openpgp.createCleartextMessage({ text: publicKey });

    const { signature } = await openpgp.sign({
      message,
      signingKeys: privKey,
      detached: true
    });

    res.json({ signature }); // .sig in armored text format
  } catch (error) {
    console.error("❌ Detached signature error:", error);
    res.status(500).json({ error: "Detached signature failed." });
  }
});

app.listen(PORT, () => {
  console.log(`🔐 PGP Key API running at http://localhost:${PORT}`);
});

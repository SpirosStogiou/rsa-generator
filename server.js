const express = require("express");
const cors = require("cors");
const openpgp = require("openpgp");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

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


app.listen(PORT, () => {
  console.log(`🔐 PGP Key API running at http://localhost:${PORT}`);
});

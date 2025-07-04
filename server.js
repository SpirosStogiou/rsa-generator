const express = require("express");
const cors = require("cors");
const openpgp = require("openpgp");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.post("/generate", async (req, res) => {
  const { email, passphrase } = req.body;

  if (!email || !passphrase) {
    return res.status(400).json({
      success: false,
      error: "Email and passphrase are required."
    });
  }

  try {
    // 1. Generate keys
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Gmail User", email }],
      passphrase,
      format: 'armored' // Explicitly request armored format
    });

    // 2. Read and decrypt private key
    const privateKeyObj = await openpgp.readPrivateKey({ 
      armoredKey: privateKey 
    });
    
    const decryptedPrivateKey = await openpgp.decryptKey({
      privateKey: privateKeyObj,
      passphrase
    });

    // 3. Create message
    const message = await openpgp.createMessage({ 
      text: publicKey 
    });

    // 4. Create detached signature (with armored format)
    const signature = await openpgp.sign({
      message,
      signingKeys: decryptedPrivateKey,
      detached: true,
      format: 'armored' // This is crucial
    });

    // 5. Return all components
    res.json({
      success: true,
      publicKey,
      privateKey,
      signature, // Now properly armored
      message: "PGP keys and signature generated successfully"
    });

  } catch (err) {
    console.error("❌ PGP Error:", err);
    res.status(500).json({
      success: false,
      error: "Key generation failed",
      details: err.message
    });
  }
});

app.get("/", (req, res) => {
  res.send("PGP Key API is running!");
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
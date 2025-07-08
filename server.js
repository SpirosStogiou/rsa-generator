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

app.post("/verify", async (req, res) => {
  const { publicKey, signature } = req.body;

  if (!publicKey || !signature) {
    return res.status(400).json({
      success: false,
      error: "publicKey and signature are required."
    });
  }

  try {
    // 1. Read public key
    const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });

    // 2. Create message (πάλι το publicKey ως μήνυμα)
    const message = await openpgp.createMessage({ text: publicKey });

    // 3. Read the signature
    const signatureObj = await openpgp.readSignature({ armoredSignature: signature });

    // 4. Verify
    const verificationResult = await openpgp.verify({
      message,
      signature: signatureObj,
      verificationKeys: publicKeyObj
    });

    const { verified, keyID } = verificationResult.signatures[0];

    try {
      await verified; // throws on bad signature
      return res.json({
        success: true,
        valid: true,
        keyID: keyID.toHex(),
        message: "Signature is valid."
      });
    } catch (err) {
      return res.json({
        success: true,
        valid: false,
        message: "Signature is INVALID.",
        details: err.message
      });
    }
  } catch (err) {
    console.error("❌ PGP Verify Error:", err);
    res.status(500).json({
      success: false,
      error: "Verification failed",
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
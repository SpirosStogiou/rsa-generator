const express = require("express");
const cors = require("cors");
const openpgp = require("openpgp");
const { Signature } = require("openpgp");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// PGP Key Generation and Signing Endpoint
app.post("/generate", async (req, res) => {
  const { email = "test@example.com", passphrase = "1234" } = req.body;

  try {
    // 1. Generate keys
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Test User", email }],
      passphrase
    });

    // 2. Load and decrypt private key
    const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const decryptedPrivateKey = await openpgp.decryptKey({
      privateKey: privKeyObj,
      passphrase
    });

    // 3. Create message (using the public key as content)
    const message = await openpgp.createMessage({ text: publicKey });

    // 4. Create detached signature
    const signature = await openpgp.sign({
      message,
      signingKeys: decryptedPrivateKey,
      detached: true
    });

    // 5. Create Signature object and Armored .sig
    const sigObj = new Signature(signature);
    const armoredSignature = await sigObj.armor();

    // Response with all generated data
    res.json({
      success: true,
      publicKey,
      privateKey,
      signature: armoredSignature,
      message: "PGP keys and signature generated successfully"
    });

  } catch (err) {
    console.error("❌ Error:", err.message || err);
    res.status(500).json({
      success: false,
      error: "Key generation or signing failed",
      details: err.message
    });
  }
});

// Verification Endpoint
app.post("/verify", async (req, res) => {
  const { publicKey, signature, originalMessage } = req.body;

  try {
    const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
    const signatureObj = await openpgp.readSignature({ armoredSignature: signature });
    const message = await openpgp.createMessage({ text: originalMessage });

    const verificationResult = await openpgp.verify({
      message,
      signature: signatureObj,
      verificationKeys: publicKeyObj
    });

    const { verified } = verificationResult.signatures[0];
    await verified; // Throws if invalid

    res.json({
      success: true,
      valid: true,
      message: "Signature is valid"
    });

  } catch (err) {
    res.status(400).json({
      success: false,
      valid: false,
      error: "Signature verification failed",
      details: err.message
    });
  }
});

// Test endpoint
app.get("/test", async (req, res) => {
  try {
    const email = "test@example.com";
    const passphrase = "1234";

    // 1. Generate keys
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Test User", email }],
      passphrase
    });

    // 2. Load and decrypt private key
    const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const decryptedPrivateKey = await openpgp.decryptKey({
      privateKey: privKeyObj,
      passphrase
    });

    // 3. Create message (using the public key as content)
    const message = await openpgp.createMessage({ text: publicKey });

    // 4. Create detached signature
    const signature = await openpgp.sign({
      message,
      signingKeys: decryptedPrivateKey,
      detached: true
    });

    // 5. Create Signature object and Armored .sig
    const sigObj = new Signature(signature);
    const armoredSignature = await sigObj.armor();

    res.json({
      test: "successful",
      publicKey,
      privateKey,
      signature: armoredSignature
    });

  } catch (err) {
    res.status(500).json({
      test: "failed",
      error: err.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`🔐 PGP Key API running at http://localhost:${PORT}`);
});
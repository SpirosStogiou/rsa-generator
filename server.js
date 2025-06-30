const express = require("express");
const fs = require("fs");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());

app.get("/public-key", (req, res) => {
  const publicKey = fs.readFileSync("public.pem", "utf8");
  res.json({ publicKey });
});

app.listen(PORT, () => {
  console.log(`🔐 RSA Public Key API is running at http://localhost:${PORT}/public-key`);
});
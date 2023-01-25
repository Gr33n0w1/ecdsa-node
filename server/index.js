const express = require("express");
const app = express();
const cors = require("cors");
const secp = require("ethereum-cryptography/secp256k1");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { utf8ToBytes } = require("ethereum-cryptography/utils");
const { toHex } = require("ethereum-cryptography/utils");
const { hexToBytes } = require("ethereum-cryptography/utils");
const port = 3042;

app.use(cors());
app.use(express.json());

const balances = {
  "4b3619ef357ee8c4ec854b21f2397d070065cb91": 100,
  "d5b9bb53de88d4f12aaa90919b995d547e081958": 50,
  "7166697984c234c9b9beff53247a9c93385a2395": 75,
  "08e0eba7ada39c6f40c688db758e52fd8a058210": 22
};

app.get("/balance/:signature", (req, res) => {
  const { signature } = req.params;
  const address = signatureToAddress(signature, "OK");
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { sign, recipient, amount } = req.body;
  const sender = signatureToAddress(sign, "OK");
  console.log("Sender Address = ", sender);
  setInitialBalance(sender);
  setInitialBalance(recipient);

  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}

/**
 * Recover the address when having the signature and the message
 * @param signature the full signature (signature + recovery bit)
 * @param message the signed message.
 * @returns the correponding address of the account who signed the message.
 */
function signatureToAddress(signature, msg) {
  // First we get the public key from the signature
  const msgHash = hashMessage(msg);
  const fullSignature = hexToBytes(signature);
  const recoveryBit = fullSignature[0];
  const signatureBytes = fullSignature.slice(1);
  const publicKey = secp.recoverPublicKey(msgHash, signatureBytes, recoveryBit);
  //Then we convert the public key to address
  const publicKeyWithoutFirstBit = publicKey.slice(1, publicKey.length);
  const keccak256PublicKey = keccak256(publicKeyWithoutFirstBit);
  const address = keccak256PublicKey.slice(-20);
  return toHex(address);
}

/**
 * Hash a message using KECCAK-256
 * @param msg the message to hash.
 * @returns the hash of the message.
 */
function hashMessage(msg) {
  return keccak256(utf8ToBytes(msg));
}

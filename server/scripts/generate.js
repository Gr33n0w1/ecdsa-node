const secp = require("ethereum-cryptography/secp256k1");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { utf8ToBytes } = require("ethereum-cryptography/utils");
const { toHex } = require("ethereum-cryptography/utils");

const privateKey = secp.utils.randomPrivateKey();
const message = "I am the first user";
const publicKey = secp.getPublicKey(privateKey);
async function signMessage(msg){
    const msgHash = keccak256(utf8ToBytes(msg));
    const sign = await secp.sign(msgHash, privateKey);
    console.log("r=", toHex(sign));
    const isVerfied = await secp.verify(sign, msgHash, publicKey);
    console.log("Isverified: ", isVerfied);
}

signMessage(message);


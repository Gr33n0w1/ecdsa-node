import * as secp from "ethereum-cryptography/secp256k1.js";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { toHex } from "ethereum-cryptography/utils.js";
import { utf8ToBytes } from "ethereum-cryptography/utils.js";

/**
 * My Utils.
 * All you'll need to test this project is signatures and addresses
 * You can use this file to generate signatures and addresses,
 * You'll need these signature to check your balance.
 * Or to validate transactions.
 */

const privateKey = secp.utils.randomPrivateKey();
console.log("Private Key = ", toHex(privateKey));
const publicKey = secp.getPublicKey(privateKey);
const address = getAddress(publicKey);
console.log("Address = ", toHex(address));
const checkBalanceMsg = "OK";

const fullSignatureHex = await signMessage(checkBalanceMsg, privateKey);
console.log("Full signature = ", fullSignatureHex);

/**
 * Hash a message using KECCAK-256
 * @param msg the message to hash.
 * @returns the hash of the message.
 */
function hashMessage(msg) {
    return keccak256(utf8ToBytes(msg));
}

/**
 * Sign a message using secp256k1 librairy
 * @param msg the message to hash.
 * @param privateKey the private key used to hash.
 * @returns the full signature in hex containing the signature and the recovery bit.
 */
async function signMessage(msg, privateKey){
    const msgHash = hashMessage(msg);
    const [signature, recoveryBit] = await secp.sign(msgHash, privateKey, {recovered: true});
    const isVerfied = await secp.verify(signature, msgHash, publicKey);
    console.log("Isverified: ", isVerfied);
    const fullSignature = new Uint8Array([recoveryBit, ...signature]);
    return toHex(fullSignature);
}

/**
 * get an ethereum address from a public key
 * @param publicKey the public key to derivate.
 * @returns the 40 characters address, we don't include the 0x at the begining.
 */
function getAddress(publicKey) {
    const publicKeyWithoutFirstBit = publicKey.slice(1, publicKey.length);
    const keccak256PublicKey = keccak256(publicKeyWithoutFirstBit);
    return keccak256PublicKey.slice(-20);
}


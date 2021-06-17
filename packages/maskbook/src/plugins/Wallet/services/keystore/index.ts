import { Buffer } from 'buffer'
import scrypt from 'scrypt-js'
import Web3Utils from 'web3-utils'
import type { CryptoKeyStore } from './types'
import { assertKeyStore, parseKeyStore } from './utils'

export async function fromKeyStore(input: string, password: Uint8Array) {
    const store = parseKeyStore(input)
    assertKeyStore(store)
    const { crypto } = store
    const derivedKey = await makeDerivedKey(crypto, password)
    if (!verifyKeyDerivation(store.crypto, derivedKey)) {
        throw new Error('Key derivation failed - possibly wrong passphrase')
    }
    const seed = await decrypt(
        store.crypto.cipher,
        derivedKey,
        Buffer.from(store.crypto.ciphertext, 'hex'),
        Buffer.from(store.crypto.cipherparams.iv, 'hex'),
    )
    return { address: `0x${store.address}`, privateKey: `0x${seed}` } as const
}

export async function decrypt(cipher: string, derivedKey: Uint8Array, ciphertext: Uint8Array, iv: Uint8Array) {
    const name = cipher === 'aes-128-ctr' ? 'AES-CTR' : 'AES-CBC'
    derivedKey = derivedKey.slice(0, 16)
    const key = await crypto.subtle.importKey('raw', derivedKey, { name, length: 128 }, false, ['decrypt'])
    const algorithm = cipher === 'aes-128-ctr' ? { name, counter: iv, length: 128 } : { name, iv }
    const seed = await crypto.subtle.decrypt(algorithm, key, ciphertext)
    return Buffer.from(seed).toString('hex')
}

async function verifyKeyDerivation(keystore: CryptoKeyStore, derivedKey: Uint8Array) {
    const cipherText = Buffer.from(keystore.ciphertext, 'hex')
    const buf = Buffer.concat([Buffer.from(derivedKey.slice(16, 32)), cipherText])
    const mac = Web3Utils.sha3(`0x${buf.toString('hex')}`)
    return mac === `0x${keystore.mac}`
}

async function makeDerivedKey(keystore: CryptoKeyStore, password: Uint8Array) {
    const salt = Buffer.from(keystore.kdfparams.salt, 'hex')
    if (keystore.kdf === 'scrypt') {
        const { n, r, p, dklen } = keystore.kdfparams
        return scrypt.scrypt(password, salt, n, r, p, dklen)
    } else if (keystore.kdf === 'pbkdf2') {
        const { prf, c } = keystore.kdfparams
        if (prf !== 'hmac-sha256') {
            throw new Error('Unsupported parameters to PBKDF2')
        }
        const key = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits'])
        const params: Pbkdf2Params = { name: 'PBKDF2', salt, iterations: c, hash: 'SHA-256' }
        return new Uint8Array(await crypto.subtle.deriveBits(params, key, 256))
    }
    throw new Error('Unsupport key derivation scheme')
}

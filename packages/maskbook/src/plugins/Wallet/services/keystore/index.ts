import { Buffer } from 'buffer'
import scrypt from 'scrypt-js'
import Web3Utils from 'web3-utils'
import type { CryptoKeyStore } from './types'
import { assertKeyStore } from './utils'

export async function fromKeyStore(input: string, password: Uint8Array) {
    let store: object
    try {
        store = JSON.parse(input)
    } catch {
        throw new Error('We donot support non-json format keystore!')
    }
    assertKeyStore(store)
    const derivedKey = await makeDerivedKey(store.crypto, password)
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
    const length = 128
    const key = await crypto.subtle.importKey('raw', derivedKey, { name, length }, false, ['decrypt'])
    const aes_ctr_params: AesCtrParams = { name, counter: iv, length }
    const aes_cbc_params: AesCbcParams = { name, iv }
    const seed = await crypto.subtle.decrypt(
        cipher === 'aes-128-ctr' ? aes_ctr_params : aes_cbc_params,
        key,
        ciphertext,
    )
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
        const iterations = keystore.kdfparams.c
        const key = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits'])
        const params: Pbkdf2Params = { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }
        return new Uint8Array(await crypto.subtle.deriveBits(params, key, 256))
    }
    throw new Error('Unsupport key derivation scheme')
}

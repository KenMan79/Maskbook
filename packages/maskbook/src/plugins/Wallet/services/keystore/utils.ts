import ZSchema from 'z-schema'
import schema from './schema.json'
import type { KeyStore } from './types'

export function assertKeyStore(input: object): asserts input is KeyStore {
    const validator = new ZSchema({})
    const valid = validator.validate(input, schema)
    if (!valid) {
        const error = validator.getLastError()
        throw new Error(error.details[0].message)
    }
}

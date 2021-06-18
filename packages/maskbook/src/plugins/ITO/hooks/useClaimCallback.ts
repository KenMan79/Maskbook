import { useCallback } from 'react'
import stringify from 'json-stable-stringify'
import type { NonPayableTx } from '@dimensiondev/contracts/types/types'
import {
    TransactionEventType,
    TransactionStateType,
    useAccount,
    useChainId,
    useTransactionState,
    useGasPrice,
    useNonce,
} from '@dimensiondev/web3-shared'
import { useITO_Contract } from '../contracts/useITO_Contract'
import { isZero } from '@dimensiondev/maskbook-shared'

export function useClaimCallback(pids: string[], contractAddress?: string) {
    const nonce = useNonce()
    const gasPrice = useGasPrice()
    const account = useAccount()
    const chainId = useChainId()
    const ITO_Contract = useITO_Contract(contractAddress)
    const [claimState, setClaimState] = useTransactionState()

    const claimCallback = useCallback(async () => {
        if (!ITO_Contract || pids.length === 0) {
            setClaimState({
                type: TransactionStateType.UNKNOWN,
            })
            return
        }
        // start waiting for provider to confirm tx
        setClaimState({
            type: TransactionStateType.WAIT_FOR_CONFIRMING,
        })

        // check if already claimed
        try {
            const availabilityList = await Promise.all(
                pids.map((pid) =>
                    ITO_Contract.methods.check_availability(pid).call({
                        from: account,
                    }),
                ),
            )

            const isClaimed = availabilityList.some((availability) => isZero(availability.swapped))

            if (isClaimed) {
                setClaimState({
                    type: TransactionStateType.FAILED,
                    error: new Error('Already Claimed'),
                })
                return
            }
        } catch (e) {
            setClaimState({
                type: TransactionStateType.FAILED,
                error: new Error('Failed to check availability.'),
            })
            return
        }

        // estimate gas and compose transaction
        const config = {
            from: account,
            gas: await ITO_Contract.methods
                .claim(pids)
                .estimateGas({
                    from: account,
                })
                .catch((error) => {
                    setClaimState({
                        type: TransactionStateType.FAILED,
                        error,
                    })
                    throw error
                }),
            gasPrice,
            nonce,
        }

        // send transaction and wait for hash
        return new Promise<void>(async (resolve, reject) => {
            const promiEvent = ITO_Contract.methods.claim(pids).send(config as NonPayableTx)

            promiEvent
                .once(TransactionEventType.TRANSACTION_HASH, (hash) => {
                    setClaimState({
                        type: TransactionStateType.HASH,
                        hash,
                    })
                })
                .once(TransactionEventType.RECEIPT, (receipt) => {
                    setClaimState({
                        type: TransactionStateType.CONFIRMED,
                        no: 0,
                        receipt,
                    })
                })
                .once(TransactionEventType.CONFIRMATION, (no, receipt) => {
                    setClaimState({
                        type: TransactionStateType.CONFIRMED,
                        no,
                        receipt,
                    })
                    resolve()
                })
                .once(TransactionEventType.ERROR, (error) => {
                    setClaimState({
                        type: TransactionStateType.FAILED,
                        error,
                    })
                    reject(error)
                })
        })
    }, [account, chainId, ITO_Contract, stringify(pids)])

    const resetCallback = useCallback(() => {
        setClaimState({
            type: TransactionStateType.UNKNOWN,
        })
    }, [])

    return [claimState, claimCallback, resetCallback] as const
}

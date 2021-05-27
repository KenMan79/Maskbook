import { useCallback, useState } from 'react'
import type { PayableTx } from '@dimensiondev/contracts/types/types'
import { useAccount } from '../../../../web3/hooks/useAccount'
import { useChainId } from '../../../../web3/hooks/useChainId'
import { TransactionState, TransactionStateType } from '../../../../web3/hooks/useTransactionState'
import { SwapResponse, TradeComputed, TradeStrategy } from '../../types'
import type { ExchangeProxy } from '@dimensiondev/contracts/types/ExchangeProxy'
import { SLIPPAGE_TOLERANCE_DEFAULT, TRADE_CONSTANTS } from '../../constants'
import { EthereumTokenType, TransactionEventType } from '../../../../web3/types'
import { useConstant } from '../../../../web3/hooks/useConstant'
import { useTradeAmount } from './useTradeAmount'
import Services from '../../../../extension/service'

export function useTradeCallback(
    trade: TradeComputed<SwapResponse> | null,
    exchangeProxyContract: ExchangeProxy | null,
    allowedSlippage = SLIPPAGE_TOLERANCE_DEFAULT,
) {
    const account = useAccount()
    const chainId = useChainId()
    const BALANCER_ETH_ADDRESS = useConstant(TRADE_CONSTANTS, 'BALANCER_ETH_ADDRESS')

    const [tradeState, setTradeState] = useState<TransactionState>({
        type: TransactionStateType.UNKNOWN,
    })
    const tradeAmount = useTradeAmount(trade, allowedSlippage)

    const tradeCallback = useCallback(async () => {
        if (!trade || !trade.inputToken || !trade.outputToken || !exchangeProxyContract) {
            setTradeState({
                type: TransactionStateType.UNKNOWN,
            })
            return
        }

        // start waiting for provider to confirm tx
        setTradeState({
            type: TransactionStateType.WAIT_FOR_CONFIRMING,
        })

        const {
            swaps: [swaps],
        } = trade.trade_ as SwapResponse

        // cast the type to ignore the different type which was generated by typechain
        const swap_: Parameters<ExchangeProxy['methods']['multihopBatchSwapExactIn']>[0] = swaps.map((x) =>
            x.map(
                (y) =>
                    [
                        y.pool, // address pool
                        y.tokenIn, // address tokenIn
                        y.tokenOut, // address tokenOut
                        y.swapAmount, // uint swapAmount
                        y.limitReturnAmount, // uint limitReturnAmount
                        y.maxPrice, // uinnt maxPrice
                    ] as [string, string, string, string, string, string],
            ),
        )

        // balancer use a different address for Ether
        const inputTokenAddress =
            trade.inputToken.type === EthereumTokenType.Native ? BALANCER_ETH_ADDRESS : trade.inputToken.address
        const outputTokenAddress =
            trade.outputToken.type === EthereumTokenType.Native ? BALANCER_ETH_ADDRESS : trade.outputToken.address

        const tx =
            trade.strategy === TradeStrategy.ExactIn
                ? exchangeProxyContract.methods.multihopBatchSwapExactIn(
                      swap_,
                      inputTokenAddress,
                      outputTokenAddress,
                      trade.inputAmount.toFixed(),
                      tradeAmount.toFixed(),
                  )
                : exchangeProxyContract.methods.multihopBatchSwapExactOut(
                      swap_,
                      inputTokenAddress,
                      outputTokenAddress,
                      tradeAmount.toFixed(),
                  )

        // trade with the native token
        let transactionValue = '0'
        if (trade.strategy === TradeStrategy.ExactIn && trade.inputToken.type === EthereumTokenType.Native)
            transactionValue = trade.inputAmount.toFixed()
        else if (trade.strategy === TradeStrategy.ExactOut && trade.outputToken.type === EthereumTokenType.Native)
            transactionValue = trade.outputAmount.toFixed()

        // send transaction and wait for hash
        const config = await Services.Ethereum.composeTransaction({
            from: account,
            to: exchangeProxyContract.options.address,
            value: transactionValue,
            data: tx.encodeABI(),
        }).catch((error: Error) => {
            setTradeState({
                type: TransactionStateType.FAILED,
                error,
            })
            throw error
        })

        // send transaction and wait for hash
        return new Promise<void>((resolve, reject) => {
            const promiEvent = tx.send(config as PayableTx)
            promiEvent
                .on(TransactionEventType.RECEIPT, (receipt) => {
                    setTradeState({
                        type: TransactionStateType.CONFIRMED,
                        no: 0,
                        receipt,
                    })
                })
                .on(TransactionEventType.CONFIRMATION, (no, receipt) => {
                    setTradeState({
                        type: TransactionStateType.CONFIRMED,
                        no,
                        receipt,
                    })
                    resolve()
                })
                .on(TransactionEventType.ERROR, (error) => {
                    setTradeState({
                        type: TransactionStateType.FAILED,
                        error,
                    })
                    reject(error)
                })
        })
    }, [chainId, trade, tradeAmount, exchangeProxyContract, BALANCER_ETH_ADDRESS])

    const resetCallback = useCallback(() => {
        setTradeState({
            type: TransactionStateType.UNKNOWN,
        })
    }, [])

    return [tradeState, tradeCallback, resetCallback] as const
}

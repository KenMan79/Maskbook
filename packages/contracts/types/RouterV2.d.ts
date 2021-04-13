/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import BN from 'bn.js'
import { Contract, ContractOptions } from 'web3-eth-contract'
import { EventLog } from 'web3-core'
import { EventEmitter } from 'events'
import { ContractEvent, Callback, TransactionObject, BlockType } from './types'

interface EventOptions {
    filter?: object
    fromBlock?: BlockType
    topics?: string[]
}

export class RouterV2 extends Contract {
    constructor(jsonInterface: any[], address?: string, options?: ContractOptions)
    clone(): RouterV2
    methods: {
        WETH(): TransactionObject<string>

        addLiquidity(
            tokenA: string,
            tokenB: string,
            amountADesired: number | string,
            amountBDesired: number | string,
            amountAMin: number | string,
            amountBMin: number | string,
            to: string,
            deadline: number | string,
        ): TransactionObject<{
            amountA: string
            amountB: string
            liquidity: string
            0: string
            1: string
            2: string
        }>

        addLiquidityETH(
            token: string,
            amountTokenDesired: number | string,
            amountTokenMin: number | string,
            amountETHMin: number | string,
            to: string,
            deadline: number | string,
        ): TransactionObject<{
            amountToken: string
            amountETH: string
            liquidity: string
            0: string
            1: string
            2: string
        }>

        factory(): TransactionObject<string>

        getAmountIn(
            amountOut: number | string,
            reserveIn: number | string,
            reserveOut: number | string,
        ): TransactionObject<string>

        getAmountOut(
            amountIn: number | string,
            reserveIn: number | string,
            reserveOut: number | string,
        ): TransactionObject<string>

        getAmountsIn(amountOut: number | string, path: string[]): TransactionObject<string[]>

        getAmountsOut(amountIn: number | string, path: string[]): TransactionObject<string[]>

        quote(amountA: number | string, reserveA: number | string, reserveB: number | string): TransactionObject<string>

        removeLiquidity(
            tokenA: string,
            tokenB: string,
            liquidity: number | string,
            amountAMin: number | string,
            amountBMin: number | string,
            to: string,
            deadline: number | string,
        ): TransactionObject<{
            amountA: string
            amountB: string
            0: string
            1: string
        }>

        removeLiquidityETH(
            token: string,
            liquidity: number | string,
            amountTokenMin: number | string,
            amountETHMin: number | string,
            to: string,
            deadline: number | string,
        ): TransactionObject<{
            amountToken: string
            amountETH: string
            0: string
            1: string
        }>

        removeLiquidityETHSupportingFeeOnTransferTokens(
            token: string,
            liquidity: number | string,
            amountTokenMin: number | string,
            amountETHMin: number | string,
            to: string,
            deadline: number | string,
        ): TransactionObject<string>

        removeLiquidityETHWithPermit(
            token: string,
            liquidity: number | string,
            amountTokenMin: number | string,
            amountETHMin: number | string,
            to: string,
            deadline: number | string,
            approveMax: boolean,
            v: number | string,
            r: string | number[],
            s: string | number[],
        ): TransactionObject<{
            amountToken: string
            amountETH: string
            0: string
            1: string
        }>

        removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(
            token: string,
            liquidity: number | string,
            amountTokenMin: number | string,
            amountETHMin: number | string,
            to: string,
            deadline: number | string,
            approveMax: boolean,
            v: number | string,
            r: string | number[],
            s: string | number[],
        ): TransactionObject<string>

        removeLiquidityWithPermit(
            tokenA: string,
            tokenB: string,
            liquidity: number | string,
            amountAMin: number | string,
            amountBMin: number | string,
            to: string,
            deadline: number | string,
            approveMax: boolean,
            v: number | string,
            r: string | number[],
            s: string | number[],
        ): TransactionObject<{
            amountA: string
            amountB: string
            0: string
            1: string
        }>

        swapETHForExactTokens(
            amountOut: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<string[]>

        swapExactETHForTokens(
            amountOutMin: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<string[]>

        swapExactETHForTokensSupportingFeeOnTransferTokens(
            amountOutMin: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<void>

        swapExactTokensForETH(
            amountIn: number | string,
            amountOutMin: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<string[]>

        swapExactTokensForETHSupportingFeeOnTransferTokens(
            amountIn: number | string,
            amountOutMin: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<void>

        swapExactTokensForTokens(
            amountIn: number | string,
            amountOutMin: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<string[]>

        swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amountIn: number | string,
            amountOutMin: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<void>

        swapTokensForExactETH(
            amountOut: number | string,
            amountInMax: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<string[]>

        swapTokensForExactTokens(
            amountOut: number | string,
            amountInMax: number | string,
            path: string[],
            to: string,
            deadline: number | string,
        ): TransactionObject<string[]>
    }
    events: {
        allEvents: (options?: EventOptions, cb?: Callback<EventLog>) => EventEmitter
    }
}

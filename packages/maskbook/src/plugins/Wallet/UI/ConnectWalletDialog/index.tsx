import { useCallback, useState } from 'react'
import { useAsyncRetry } from 'react-use'
import { makeStyles, DialogContent } from '@material-ui/core'
import { useStylesExtends } from '../../../../components/custom-ui-helper'
import { InjectedDialog } from '../../../../components/shared/InjectedDialog'
import { delay, useI18N, useRemoteControlledDialog, useValueRef } from '../../../../utils'
import {
    NetworkType,
    ProviderType,
    getChainIdFromNetworkType,
    resolveProviderName,
    useAccount,
    useChainId,
    ChainId,
    resolveNetworkName,
} from '@dimensiondev/web3-shared'
import { WalletMessages } from '../../messages'
import { ConnectionProgress } from './ConnectionProgress'
import Services from '../../../../extension/service'
import CHAINS from '../../../../web3/assets/chains.json'
import { safeUnreachable } from '@dimensiondev/maskbook-shared'

const useStyles = makeStyles((theme) => ({
    content: {
        padding: theme.spacing(5),
    },
}))

export interface ConnectWalletDialogProps {}

export function ConnectWalletDialog(props: ConnectWalletDialogProps) {
    const { t } = useI18N()
    const classes = useStylesExtends(useStyles(), props)

    const [providerType, setProviderType] = useState<ProviderType | undefined>()
    const [networkType, setNetworkType] = useState<NetworkType | undefined>()

    //#region remote controlled dialog
    const { open, closeDialog } = useRemoteControlledDialog(WalletMessages.events.connectWalletDialogUpdated, (ev) => {
        if (!ev.open) return
        setProviderType(ev.providerType)
        setNetworkType(ev.networkType)
    })
    //#endregion

    //#region wallet status dialog
    const { openDialog: openWalletStatusDialog } = useRemoteControlledDialog(
        WalletMessages.events.walletStatusDialogUpdated,
    )
    //#endregion

    //#region walletconnect
    const { setDialog: setWalletConnectDialog } = useRemoteControlledDialog(
        WalletMessages.events.walletConnectQRCodeDialogUpdated,
    )
    //#endregion

    const connectTo = useCallback(
        async (providerType: ProviderType) => {
            // unknown network type
            if (!networkType) throw new Error('Unknown network type.')

            // read the chain detailed from the built-in chain list
            const chainDetailed = CHAINS.find((x) => x.chainId === getChainIdFromNetworkType(networkType))
            if (!chainDetailed) throw new Error('The selected network is not supported.')

            let account: string | undefined
            let chainId: ChainId | undefined

            switch (providerType) {
                case ProviderType.Maskbook:
                    throw new Error('Not necessary!')
                case ProviderType.MetaMask:
                    ;({ account, chainId } = await Services.Ethereum.connectMetaMask())
                    break
                case ProviderType.WalletConnect:
                    // a short time loading makes the user fells better
                    const [uri_] = await Promise.allSettled([Services.Ethereum.createConnectionURI(), delay(1000)])

                    // create wallet connect QR code URI
                    const uri = uri_.status === 'fulfilled' ? uri_.value : ''
                    if (!uri) throw new Error('Failed to create connection URI.')

                    // open the QR code dialog
                    setWalletConnectDialog({
                        open: true,
                        uri,
                    })

                    // wait for walletconnect to be connected
                    ;({ account, chainId } = await Services.Ethereum.connectWalletConnect())
                    break
                case ProviderType.CustomNetwork:
                    throw new Error('To be implemented.')
                default:
                    safeUnreachable(providerType)
                    break
            }

            // connection failed
            if (!account || !networkType) throw new Error(`Failed to connect ${resolveProviderName(providerType)}.`)

            if (networkType === NetworkType.Ethereum) {
                // it's unable to send a request for switching to ethereum networks
                if (chainId !== ChainId.Mainnet)
                    throw new Error(
                        `Make sure you've selected the Ethereum Mainnet on ${resolveProviderName(providerType)}.`,
                    )
                return true
            }

            // request ethereum-compatiable network
            try {
                await Services.Ethereum.addEthereumChain(account, {
                    chainId: `0x${chainDetailed.chainId.toString(16)}`,
                    chainName: chainDetailed.name,
                    nativeCurrency: chainDetailed.nativeCurrency,
                    rpcUrls: chainDetailed.rpc,
                    blockExplorerUrls: [
                        chainDetailed.explorers && chainDetailed.explorers.length > 0 && chainDetailed.explorers[0].url
                            ? chainDetailed.explorers[0].url
                            : chainDetailed.infoURL,
                    ],
                })
            } catch (e) {
                throw new Error(`Connection error! Please switch to ${resolveNetworkName(networkType)} manually.`)
            }

            // wait for settings to be synced
            await delay(1000)

            return true as const
        },
        [networkType],
    )

    const connection = useAsyncRetry<true>(async () => {
        if (!open) return true
        if (!providerType) throw new Error('Unknown provider type.')

        // connect to the specific provider
        await connectTo(providerType)

        // switch to the wallet status dialog
        closeDialog()
        openWalletStatusDialog()

        return true
    }, [open, providerType, connectTo, openWalletStatusDialog])

    if (!providerType) return null

    return (
        <InjectedDialog title={`Connect to ${resolveProviderName(providerType)}`} open={open} onClose={closeDialog}>
            <DialogContent className={classes.content}>
                <ConnectionProgress providerType={providerType} connection={connection} />
            </DialogContent>
        </InjectedDialog>
    )
}

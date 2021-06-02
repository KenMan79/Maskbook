import { memo } from 'react'
import type { Asset } from '../../types'
import { Box, TableRow, Typography, makeStyles, TableCell, Button } from '@material-ui/core'
import { TokenIcon } from '../TokenIcon'
import { formatBalance, formatCurrency } from '@dimensiondev/maskbook-shared'
import { CurrencyType } from '@dimensiondev/web3-shared'
import BigNumber from 'bignumber.js'
import { useHistory } from 'react-router'
import { Routes } from '../../../../type'

const useStyles = makeStyles((theme) => ({
    symbol: {
        marginLeft: 14,
        fontSize: theme.typography.pxToRem(14),
    },
    cell: {
        padding: '16px 28px',
    },
}))

export interface TokenTableRowProps {
    asset: Asset
}

export const TokenTableRow = memo<TokenTableRowProps>(({ asset }) => {
    const classes = useStyles()
    const history = useHistory()
    return (
        <TableRow>
            <TableCell className={classes.cell} align="center" variant="body">
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <TokenIcon
                        address={asset.token.address}
                        name={asset.token.name}
                        chainId={asset.token.chainId}
                        AvatarProps={{ sx: { width: 36, height: 36 } }}
                    />
                    <Typography className={classes.symbol}>{asset.token.symbol}</Typography>
                </Box>
            </TableCell>
            <TableCell className={classes.cell} align="center" variant="body">
                <Typography>{new BigNumber(formatBalance(asset.balance, asset.token.decimals)).toFixed(6)}</Typography>
            </TableCell>
            <TableCell className={classes.cell} align="center" variant="body">
                <Typography>
                    {asset.price?.[CurrencyType.USD]
                        ? new BigNumber(asset.price[CurrencyType.USD]).gt(new BigNumber(10).pow(-6))
                            ? formatCurrency(Number.parseFloat(asset.price[CurrencyType.USD]), '$')
                            : '<0.000001'
                        : '-'}
                </Typography>
            </TableCell>
            <TableCell className={classes.cell} align="center">
                <Typography>
                    {new BigNumber(formatBalance(asset.balance, asset.token.decimals)).isLessThan(0.01)
                        ? '<0.01'
                        : new BigNumber(formatBalance(asset.balance, asset.token.decimals)).toFixed(2)}
                </Typography>
            </TableCell>
            <TableCell className={classes.cell} align="center" variant="body">
                <Button
                    variant="outlined"
                    color="secondary"
                    sx={{ marginRight: 1 }}
                    onClick={() => history.push(Routes.WalletsTransfer)}>
                    Send
                </Button>
                <Button variant="outlined" color="secondary">
                    Swap
                </Button>
            </TableCell>
        </TableRow>
    )
})

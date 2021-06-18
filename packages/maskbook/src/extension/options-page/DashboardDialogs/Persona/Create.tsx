import { TextField } from '@material-ui/core'
import { ChangeEvent, useCallback, useState } from 'react'
import { UserPlus } from 'react-feather'
import { useHistory } from 'react-router-dom'
import { WALLET_OR_PERSONA_NAME_MAX_LEN, useI18N, checkInputLengthExceed } from '../../../../utils'
import Services from '../../../service'
import { DebounceButton } from '../../DashboardComponents/ActionButton'
import { DashboardRoute } from '../../Route'
import { SetupStep } from '../../SetupStep'
import { DashboardDialogCore, DashboardDialogWrapper, WrappedDialogProps } from '../Base'

export function DashboardPersonaCreateDialog(props: WrappedDialogProps) {
    const { t } = useI18N()
    const [name, setName] = useState('')
    const history = useHistory<unknown>()

    const createPersonaAndNext = async () => {
        const persona = await Services.Identity.createPersonaByMnemonic(name, '')
        history.push(
            `${DashboardRoute.Setup}/${SetupStep.ConnectNetwork}?identifier=${encodeURIComponent(persona.toText())}`,
        )
    }

    const onChange = useCallback((ev: ChangeEvent<HTMLInputElement>) => {
        if (ev.currentTarget.value.length > WALLET_OR_PERSONA_NAME_MAX_LEN) {
            return
        }
        setName(ev.currentTarget.value)
    }, [])

    return (
        <DashboardDialogCore fullScreen={false} {...props}>
            <DashboardDialogWrapper
                icon={<UserPlus />}
                iconColor="#5FDD97"
                primary={t('create_a_persona')}
                secondary={' '}
                content={
                    <>
                        <form>
                            <TextField
                                helperText={
                                    checkInputLengthExceed(name)
                                        ? t('input_length_exceed_prompt', {
                                              name: t('persona_name').toLowerCase(),
                                              length: WALLET_OR_PERSONA_NAME_MAX_LEN,
                                          })
                                        : undefined
                                }
                                style={{ marginBottom: 20 }}
                                autoFocus
                                required
                                label={t('name')}
                                value={name}
                                onChange={onChange}
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                        e.preventDefault()
                                        createPersonaAndNext()
                                    }
                                }}
                                variant="outlined"
                            />
                        </form>
                    </>
                }
                footer={
                    <DebounceButton
                        type="submit"
                        variant="contained"
                        onClick={createPersonaAndNext}
                        disabled={name.length === 0 || checkInputLengthExceed(name)}>
                        {t('create')}
                    </DebounceButton>
                }></DashboardDialogWrapper>
        </DashboardDialogCore>
    )
}

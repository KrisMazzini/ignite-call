/* eslint-disable camelcase */

/*
    - Para acessar as APIs do Google precisamos do Access Token, mas ele já pode ter expirado
    - Precisamos então renovar o Access Token usando o Refresh Token
    - A função abaixo sempre será chamada quando quisermos nos comunicar com as APIs do Google
    - Ela irá automatizar o processo de verificar se o Token já expirou e renová-lo se necessário
*/

import { google } from 'googleapis'
import { prisma } from './prisma'
import dayjs from 'dayjs'

export async function getGoogleOAuthToken(userId: string) {
  const account = await prisma.account.findFirstOrThrow({
    where: {
      provider: 'google',
      user_id: userId,
    },
  })

  const auth = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
  )

  auth.setCredentials({
    access_token: account.access_token,
    refresh_token: account.refresh_token,
    expiry_date: account.expires_at ? account.expires_at * 1000 : null,
  })

  if (!account.expires_at) {
    return auth
  }

  const hasAccessTokenExpired = dayjs(account.expires_at * 1000).isBefore(
    new Date(),
  ) // Google's expiry_date is in seconds, not milliseconds

  if (hasAccessTokenExpired) {
    const { credentials } = await auth.refreshAccessToken()
    const {
      access_token,
      refresh_token,
      expiry_date,
      id_token,
      scope,
      token_type,
    } = credentials

    await prisma.account.update({
      where: {
        id: account.id,
      },
      data: {
        access_token,
        refresh_token,
        expires_at: expiry_date ? Math.floor(expiry_date / 1000) : null,
        id_token,
        scope,
        token_type,
      },
    })

    auth.setCredentials({
      access_token,
      refresh_token,
      expiry_date,
    })
  }

  return auth
}

import type { HoaContext, HoaMiddleware } from 'hoa'

export interface XFrameOptionsOptions {
  action?: 'deny' | 'sameorigin';
}

function getHeaderValueFromOptions ({
  action = 'sameorigin',
}: Readonly<XFrameOptionsOptions>): string {
  const normalizedAction =
        typeof action === 'string' ? action.toUpperCase() : action

  switch (normalizedAction) {
    case 'SAME-ORIGIN':
      return 'SAMEORIGIN'
    case 'DENY':
    case 'SAMEORIGIN':
      return normalizedAction
    default:
      throw new Error(
                `X-Frame-Options received an invalid action ${JSON.stringify(action)}`
      )
  }
}

export function xFrameOptions (options: Readonly<XFrameOptionsOptions> = {}): HoaMiddleware {
  const headerValue = getHeaderValueFromOptions(options)

  return async function xFrameOptionsMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('X-Frame-Options', headerValue)
    await next()
  }
}

export default xFrameOptions

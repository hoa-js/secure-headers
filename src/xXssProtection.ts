import type { HoaContext, HoaMiddleware } from 'hoa'

export function xXssProtection (): HoaMiddleware {
  return async function xXssProtectionMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('X-XSS-Protection', '0')
    await next()
  }
}

export default xXssProtection

import type { HoaContext, HoaMiddleware } from 'hoa'

export function xContentTypeOptions (): HoaMiddleware {
  return async function xContentTypeOptionsMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('X-Content-Type-Options', 'nosniff')
    await next()
  }
}

export default xContentTypeOptions

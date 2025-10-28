import type { HoaContext, HoaMiddleware } from 'hoa'

export function xDownloadOptions (): HoaMiddleware {
  return async function xDownloadOptionsMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('X-Download-Options', 'noopen')
    await next()
  }
}

export default xDownloadOptions

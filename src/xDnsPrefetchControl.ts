import type { HoaContext, HoaMiddleware } from 'hoa'

export interface XDnsPrefetchControlOptions {
  allow?: boolean;
}

export function xDnsPrefetchControl (
  options: Readonly<XDnsPrefetchControlOptions> = {}
): HoaMiddleware {
  const headerValue = options.allow ? 'on' : 'off'

  return async function xDnsPrefetchControlMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('X-DNS-Prefetch-Control', headerValue)
    await next()
  }
}

export default xDnsPrefetchControl

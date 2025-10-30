import type { HoaContext, HoaMiddleware } from 'hoa'

export interface CrossOriginOpenerPolicyOptions {
  policy?: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none'
}
const ALLOWED_POLICIES = new Set(['same-origin', 'same-origin-allow-popups', 'unsafe-none'])

function getHeaderValueFromOptions ({
  policy = 'same-origin',
}: Readonly<CrossOriginOpenerPolicyOptions>): string {
  if (ALLOWED_POLICIES.has(policy)) {
    return policy
  } else {
    throw new Error(
      `Cross-Origin-Opener-Policy does not support the ${JSON.stringify(
        policy
      )} policy`
    )
  }
}

export function crossOriginOpenerPolicy (
  options: Readonly<CrossOriginOpenerPolicyOptions> = {}
): HoaMiddleware {
  const headerValue = getHeaderValueFromOptions(options)

  return async function crossOriginOpenerPolicyMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('Cross-Origin-Opener-Policy', headerValue)
    await next()
  }
}

export default crossOriginOpenerPolicy

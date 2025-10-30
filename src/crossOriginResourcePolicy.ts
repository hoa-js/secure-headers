import type { HoaContext, HoaMiddleware } from 'hoa'

export interface CrossOriginResourcePolicyOptions {
  policy?: 'same-origin' | 'same-site' | 'cross-origin'
}
const ALLOWED_POLICIES = new Set(['same-origin', 'same-site', 'cross-origin'])

function getHeaderValueFromOptions ({
  policy = 'same-origin',
}: Readonly<CrossOriginResourcePolicyOptions>): string {
  if (ALLOWED_POLICIES.has(policy)) {
    return policy
  } else {
    throw new Error(
      `Cross-Origin-Resource-Policy does not support the ${JSON.stringify(
        policy
      )} policy`
    )
  }
}

export function crossOriginResourcePolicy (
  options: Readonly<CrossOriginResourcePolicyOptions> = {}
): HoaMiddleware {
  const headerValue = getHeaderValueFromOptions(options)

  return async function crossOriginResourcePolicyMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('Cross-Origin-Resource-Policy', headerValue)
    await next()
  }
}

export default crossOriginResourcePolicy

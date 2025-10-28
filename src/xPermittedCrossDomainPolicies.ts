import type { HoaContext, HoaMiddleware } from 'hoa'

export interface XPermittedCrossDomainPoliciesOptions {
  permittedPolicies?: 'none' | 'master-only' | 'by-content-type' | 'all';
}

const ALLOWED_PERMITTED_POLICIES = new Set([
  'none',
  'master-only',
  'by-content-type',
  'all',
])

function getHeaderValueFromOptions ({
  permittedPolicies = 'none',
}: Readonly<XPermittedCrossDomainPoliciesOptions>): string {
  if (ALLOWED_PERMITTED_POLICIES.has(permittedPolicies)) {
    return permittedPolicies
  } else {
    throw new Error(
            `X-Permitted-Cross-Domain-Policies does not support ${JSON.stringify(
                permittedPolicies
            )}`
    )
  }
}

export function xPermittedCrossDomainPolicies (
  options: Readonly<XPermittedCrossDomainPoliciesOptions> = {}
): HoaMiddleware {
  const headerValue = getHeaderValueFromOptions(options)

  return async function xPermittedCrossDomainPoliciesMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('X-Permitted-Cross-Domain-Policies', headerValue)
    await next()
  }
}

export default xPermittedCrossDomainPolicies

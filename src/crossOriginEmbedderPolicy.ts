import type { HoaContext, HoaMiddleware } from 'hoa'

export interface CrossOriginEmbedderPolicyOptions {
  policy?: 'require-corp' | 'credentialless' | 'unsafe-none'
}
const ALLOWED_POLICIES = new Set([
  'require-corp',
  'credentialless',
  'unsafe-none',
])

function getHeaderValueFromOptions ({
  policy = 'require-corp',
}: Readonly<CrossOriginEmbedderPolicyOptions>): string {
  if (ALLOWED_POLICIES.has(policy)) {
    return policy
  } else {
    throw new Error(
      `Cross-Origin-Embedder-Policy does not support the ${JSON.stringify(
        policy
      )} policy`
    )
  }
}

export function crossOriginEmbedderPolicy (
  options: Readonly<CrossOriginEmbedderPolicyOptions> = {}
): HoaMiddleware {
  const headerValue = getHeaderValueFromOptions(options)

  return async function crossOriginEmbedderPolicyMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('Cross-Origin-Embedder-Policy', headerValue)
    await next()
  }
}

export default crossOriginEmbedderPolicy

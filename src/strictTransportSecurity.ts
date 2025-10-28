import type { HoaContext, HoaMiddleware } from 'hoa'

const DEFAULT_MAX_AGE = 365 * 24 * 60 * 60

export interface StrictTransportSecurityOptions {
  maxAge?: number;
  includeSubDomains?: boolean;
  preload?: boolean;
}

function parseMaxAge (value: number = DEFAULT_MAX_AGE): number {
  if (value >= 0 && Number.isFinite(value)) {
    return Math.floor(value)
  } else {
    throw new Error(
            `Strict-Transport-Security: ${JSON.stringify(
                value
            )} is not a valid value for maxAge. Please choose a positive integer.`
    )
  }
}

function getHeaderValueFromOptions (
  options: Readonly<StrictTransportSecurityOptions>
): string {
  if ('maxage' in options) {
    throw new Error(
      'Strict-Transport-Security received an unsupported property, `maxage`. Did you mean to pass `maxAge`?'
    )
  }
  if ('includeSubdomains' in options) {
    throw new Error(
      'Strict-Transport-Security middleware should use `includeSubDomains` instead of `includeSubdomains`. (The correct one has an uppercase "D".)'
    )
  }

  const directives: string[] = [`max-age=${parseMaxAge(options.maxAge)}`]

  if (options.includeSubDomains === undefined || options.includeSubDomains) {
    directives.push('includeSubDomains')
  }

  if (options.preload) {
    directives.push('preload')
  }

  return directives.join('; ')
}

export function strictTransportSecurity (
  options: Readonly<StrictTransportSecurityOptions> = {}
): HoaMiddleware {
  const headerValue = getHeaderValueFromOptions(options)

  return async function strictTransportSecurityMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('Strict-Transport-Security', headerValue)
    await next()
  }
}

export default strictTransportSecurity

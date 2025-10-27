import type { HoaContext, HoaMiddleware } from 'hoa'

const dashify = (str: string) => str.replace(/([A-Z])/g, '-$1').toLowerCase()
const SHOULD_QUOTE_DIRECTIVE_VALUE = new Set([
  'none',
  'self',
  'strict-dynamic',
  'report-sample',
  'inline-speculation-rules',
  'unsafe-inline',
  'unsafe-eval',
  'unsafe-hashes',
  'wasm-unsafe-eval',
])
const isValidDirectiveValueEntry = (ctx: HoaContext, directiveName: string, directiveValue: string): void => {
  const prefix = ['nonce-', 'sha256-', 'sha384-', 'sha512-']
  if (SHOULD_QUOTE_DIRECTIVE_VALUE.has(directiveValue) || prefix.some((p) => directiveValue.startsWith(p))) {
    ctx.throw(500, `
            Content-Security-Policy received an invalid directive value for ${JSON.stringify(directiveName)}: ${JSON.stringify(directiveValue)}
        `)
  }
}
const isValidDirectiveValue = (ctx: HoaContext, directiveName: string, directiveValue: string): void => {
  if (/;|,/.test(directiveValue)) {
    ctx.throw(500, `
            Content-Security-Policy received an invalid directive value for ${JSON.stringify(directiveName)}: ${JSON.stringify(directiveValue)}
        `)
  }
}
const getDefaultDirectives = () => ({
  'default-src': ["'self'"],
  'base-uri': ["'self'"],
  'font-src': ["'self'", 'https:', 'data:'],
  'form-action': ["'self'"],
  'frame-ancestors': ["'self'"],
  'img-src': ["'self'", 'data:'],
  'object-src': ["'none'"],
  'script-src': ["'self'"],
  'script-src-attr': ["'none'"],
  'style-src': ["'self'", 'https:', "'unsafe-inline'"],
  'upgrade-insecure-requests': [],
})
type ContentSecurityPolicyDirectiveValue = Iterable<string | ((ctx: HoaContext) => string)>

const dangerouslyDisableDefaultSrc = Symbol('dangerouslyDisableDefaultSrc')

export interface ContentSecurityPolicyOptions {
  useDefaults?: boolean;
  directives?: Record<
        string,
        | null
        | ContentSecurityPolicyDirectiveValue
        | typeof dangerouslyDisableDefaultSrc
    >;
  reportOnly?: boolean;
}
export function contentSecurityPolicy (options: ContentSecurityPolicyOptions = {}): HoaMiddleware {
  const headerName = options.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy'
  return async function contentSecurityPolicyMiddleware (ctx: HoaContext, next) {
    await next()
    const normalizedDirectives = normalizeDirectives(ctx, options)
    const headers = getHeaderValue(ctx, normalizedDirectives)
    ctx.res.set(headerName, headers)
  }
}

function normalizeDirectives (ctx: HoaContext, options: ContentSecurityPolicyOptions) {
  const useDefaults = options.useDefaults ?? true
  const defaultDirectives = getDefaultDirectives()
  const rawDirectives = options.directives ?? defaultDirectives

  const result = new Map<string, ContentSecurityPolicyDirectiveValue>()
  const uniqueDirectiveNames = new Set<string>()
  const explictDisabledDirectives = new Set<string>()

  for (const rawDirectiveName in rawDirectives) {
    if (!Object.hasOwn(rawDirectives, rawDirectiveName)) {
      continue
    }

    if (!rawDirectiveName || /[^a-zA-Z0-9-]/.test(rawDirectiveName)) {
      ctx.throw(
        500,
                `
                Content-Security-Policy received an invalid directive name: ${JSON.stringify(rawDirectiveName)}
                `
      )
    }

    const directiveName = dashify(rawDirectiveName)

    if (uniqueDirectiveNames.has(directiveName)) {
      ctx.throw(
        500,
                `
                Content-Security-Policy received a duplicate directive: ${JSON.stringify(directiveName)}
                `
      )
    }
    uniqueDirectiveNames.add(directiveName)

    const rawDirectiveValue = rawDirectives[rawDirectiveName]
    let directiveValue: ContentSecurityPolicyDirectiveValue

    if (rawDirectiveValue === null) {
      if (directiveName === 'default-src') {
        ctx.throw(
          500,
                    `Content-Security-Policy needs a default-src but it was set to 'null'.
                    If you really want to disable it, set it value to 'contentSecurityPolicy.dangerouslyDisableDefaultSrc'`
        )
      }
      explictDisabledDirectives.add(directiveName)
      continue
    } else if (typeof rawDirectiveValue === 'string') {
      directiveValue = [rawDirectiveValue]
    } else if (rawDirectiveValue === dangerouslyDisableDefaultSrc) {
      if (directiveName === 'default-src') {
        explictDisabledDirectives.add('default-src')
        continue
      } else {
        ctx.throw(
          500,
                    `
                    Content-Security-Policy: tried to disable ${JSON.stringify(directiveName)} as if it were default-src; simply omit the key
                    `
        )
      }
    } else if (!rawDirectiveValue) {
      ctx.throw(
        500,
                `
                Content-Security-Policy received an invalid directive value for ${JSON.stringify(directiveName)}: ${JSON.stringify(rawDirectiveValue)}
                `
      )
    } else {
      directiveValue = rawDirectiveValue
    }

    for (const v of directiveValue) {
      if (typeof v !== 'string') continue
      isValidDirectiveValue(ctx, directiveName, v)
      isValidDirectiveValueEntry(ctx, directiveName, v)
    }
    result.set(directiveName, directiveValue)
  }

  if (useDefaults) {
    Object.entries(defaultDirectives).forEach(([defaultDirectiveName, defaultDirectiveValue]) => {
      if (!result.has(defaultDirectiveName) && !explictDisabledDirectives.has(defaultDirectiveName)) {
        result.set(defaultDirectiveName, defaultDirectiveValue)
      }
    })
  }

  if (!result.size) {
    ctx.throw(500, 'Content-Security-Policy has no directives. Either set some or disable it')
  }

  if (!result.has('default-src') && !explictDisabledDirectives.has('default-src')) {
    ctx.throw(500,
            `
          Content-Security-Policy needs a default-src but none was provided.
          If you really want to disable it, set it to 'contentSecurityPolicy.dangerouslyDisableDefaultSrc'
          `
    )
  }

  return result
}

function getHeaderValue (ctx: HoaContext, directives: ReturnType<typeof normalizeDirectives>): string {
  const result: string[] = []

  for (const [directiveName, rawDirectiveValue] of directives) {
    let directiveValue = ''
    for (const v of rawDirectiveValue) {
      if (typeof v === 'function') {
        const _value = v(ctx)
        isValidDirectiveValue(ctx, directiveName, _value)
        isValidDirectiveValueEntry(ctx, directiveName, _value)
        directiveValue += ' ' + _value
      } else {
        directiveValue += ' ' + v
      }
    }
    if (directiveValue) {
      isValidDirectiveValue(ctx, directiveName, directiveValue)
      result.push(`${directiveName}${directiveValue}`)
    } else {
      result.push(directiveName)
    }
  }

  return result.join('; ')
}
contentSecurityPolicy.dangerouslyDisableDefaultSrc = dangerouslyDisableDefaultSrc
contentSecurityPolicy.getDefaultDirectives = getDefaultDirectives
export default contentSecurityPolicy

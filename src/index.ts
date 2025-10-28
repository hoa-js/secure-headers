import type { HoaContext, HoaMiddleware } from 'hoa'
import { compose } from 'hoa'
import contentSecurityPolicy, {
  type ContentSecurityPolicyOptions,
} from './contentSecurityPolicy.js'
import crossOriginEmbedderPolicy, {
  type CrossOriginEmbedderPolicyOptions,
} from './crossOriginEmbedderPolicy.js'
import crossOriginOpenerPolicy, {
  type CrossOriginOpenerPolicyOptions,
} from './crossOriginOpenerPolicy.js'
import crossOriginResourcePolicy, {
  type CrossOriginResourcePolicyOptions,
} from './crossOriginResourcePolicy.js'
import originAgentCluster from './originAgentCluster.js'
import referrerPolicy, {
  type ReferrerPolicyOptions,
} from './referrerPolicy.js'
import strictTransportSecurity, {
  type StrictTransportSecurityOptions,
} from './strictTransportSecurity.js'
import xContentTypeOptions from './xContentTypeOptions.js'
import xDnsPrefetchControl, {
  type XDnsPrefetchControlOptions,
} from './xDnsPrefetchControl.js'
import xDownloadOptions from './xDownloadOptions.js'
import xFrameOptions, {
  type XFrameOptionsOptions,
} from './xFrameOptions.js'
import xPermittedCrossDomainPolicies, {
  type XPermittedCrossDomainPoliciesOptions,
} from './xPermittedCrossDomainPolicies.js'
import xXssProtection from './xXssProtection.js'
import permissionPolicy, { type PermissionPolicyOptions } from './permissionPolicy.js'

export type SecureHeadersOptions = {
  contentSecurityPolicy?: ContentSecurityPolicyOptions | boolean;
  crossOriginEmbedderPolicy?: CrossOriginEmbedderPolicyOptions | boolean;
  crossOriginOpenerPolicy?: CrossOriginOpenerPolicyOptions | boolean;
  crossOriginResourcePolicy?: CrossOriginResourcePolicyOptions | boolean;
  originAgentCluster?: boolean;
  referrerPolicy?: ReferrerPolicyOptions | boolean;
  permissionPolicy?: PermissionPolicyOptions;
} & (
  | {
    strictTransportSecurity?: StrictTransportSecurityOptions | boolean;
    hsts?: never;
  }
  | {
    hsts?: StrictTransportSecurityOptions | boolean;
    strictTransportSecurity?: never;
  }
) &
  (
    | { xContentTypeOptions?: boolean; noSniff?: never }
    | { noSniff?: boolean; xContentTypeOptions?: never }
  ) &
  (
    | {
      xDnsPrefetchControl?: XDnsPrefetchControlOptions | boolean;
      dnsPrefetchControl?: never;
    }
    | {
      dnsPrefetchControl?: XDnsPrefetchControlOptions | boolean;
      xDnsPrefetchControl?: never;
    }
  ) &
  (
    | { xDownloadOptions?: boolean; ieNoOpen?: never }
    | { ieNoOpen?: boolean; xDownloadOptions?: never }
  ) &
  (
    | { xFrameOptions?: XFrameOptionsOptions | boolean; frameguard?: never }
    | { frameguard?: XFrameOptionsOptions | boolean; xFrameOptions?: never }
  ) &
  (
    | {
      xPermittedCrossDomainPolicies?:
          | XPermittedCrossDomainPoliciesOptions
          | boolean;
      permittedCrossDomainPolicies?: never;
    }
    | {
      permittedCrossDomainPolicies?:
          | XPermittedCrossDomainPoliciesOptions
          | boolean;
      xPermittedCrossDomainPolicies?: never;
    }
  ) &
  (
    | { xPoweredBy?: boolean; hidePoweredBy?: never }
    | { hidePoweredBy?: boolean; xPoweredBy?: never }
  ) &
  (
    | { xXssProtection?: boolean; xssFilter?: never }
    | { xssFilter?: boolean; xXssProtection?: never }
  )

interface SecureHeaders {
  (options?: SecureHeadersOptions): HoaMiddleware;
  contentSecurityPolicy: typeof contentSecurityPolicy;
  crossOriginEmbedderPolicy: typeof crossOriginEmbedderPolicy;
  crossOriginOpenerPolicy: typeof crossOriginOpenerPolicy;
  crossOriginResourcePolicy: typeof crossOriginResourcePolicy;
  originAgentCluster: typeof originAgentCluster;
  referrerPolicy: typeof referrerPolicy;
  strictTransportSecurity: typeof strictTransportSecurity;
  xContentTypeOptions: typeof xContentTypeOptions;
  xDnsPrefetchControl: typeof xDnsPrefetchControl;
  xDownloadOptions: typeof xDownloadOptions;
  xFrameOptions: typeof xFrameOptions;
  xPermittedCrossDomainPolicies: typeof xPermittedCrossDomainPolicies;
  xXssProtection: typeof xXssProtection;
  permissionPolicy: typeof permissionPolicy;
  // Legacy aliases
  dnsPrefetchControl: typeof xDnsPrefetchControl;
  frameguard: typeof xFrameOptions;
  hsts: typeof strictTransportSecurity;
  ieNoOpen: typeof xDownloadOptions;
  noSniff: typeof xContentTypeOptions;
  permittedCrossDomainPolicies: typeof xPermittedCrossDomainPolicies;
  xssFilter: typeof xXssProtection;
}

function getMiddlewareFunctionsFromOptions (options: Readonly<SecureHeadersOptions>): HoaMiddleware[] {
  const result: HoaMiddleware[] = []

  switch (options.contentSecurityPolicy) {
    case undefined:
    case true:
      result.push(contentSecurityPolicy())
      break
    case false:
      break
    default:
      result.push(contentSecurityPolicy(options.contentSecurityPolicy))
      break
  }

  switch (options.crossOriginEmbedderPolicy) {
    case undefined:
    case false:
      break
    case true:
      result.push(crossOriginEmbedderPolicy())
      break
    default:
      result.push(crossOriginEmbedderPolicy(options.crossOriginEmbedderPolicy))
      break
  }

  switch (options.crossOriginOpenerPolicy) {
    case undefined:
    case true:
      result.push(crossOriginOpenerPolicy())
      break
    case false:
      break
    default:
      result.push(crossOriginOpenerPolicy(options.crossOriginOpenerPolicy))
      break
  }

  switch (options.crossOriginResourcePolicy) {
    case undefined:
    case true:
      result.push(crossOriginResourcePolicy())
      break
    case false:
      break
    default:
      result.push(crossOriginResourcePolicy(options.crossOriginResourcePolicy))
      break
  }

  switch (options.originAgentCluster) {
    case undefined:
    case true:
      result.push(originAgentCluster())
      break
    case false:
      break
    default:
      console.warn(
        'Origin-Agent-Cluster does not take options. Remove the property to silence this warning.'
      )
      result.push(originAgentCluster())
      break
  }

  switch (options.referrerPolicy) {
    case undefined:
    case true:
      result.push(referrerPolicy())
      break
    case false:
      break
    default:
      result.push(referrerPolicy(options.referrerPolicy))
      break
  }

  if ('strictTransportSecurity' in options && 'hsts' in options) {
    throw new Error(
      'Strict-Transport-Security option was specified twice. Remove the `hsts` option to fix this error.'
    )
  }
  const strictTransportSecurityOption =
      options.strictTransportSecurity ?? options.hsts
  switch (strictTransportSecurityOption) {
    case undefined:
    case true:
      result.push(strictTransportSecurity())
      break
    case false:
      break
    default:
      result.push(strictTransportSecurity(strictTransportSecurityOption))
      break
  }

  if ('xContentTypeOptions' in options && 'noSniff' in options) {
    throw new Error(
      'X-Content-Type-Options option was specified twice. Remove the `noSniff` option to fix this error.'
    )
  }
  const xContentTypeOptionsOption =
      options.xContentTypeOptions ?? options.noSniff
  switch (xContentTypeOptionsOption) {
    case undefined:
    case true:
      result.push(xContentTypeOptions())
      break
    case false:
      break
    default:
      console.warn(
        'X-Content-Type-Options does not take options. Remove the property to silence this warning.'
      )
      result.push(xContentTypeOptions())
      break
  }

  if ('xDnsPrefetchControl' in options && 'dnsPrefetchControl' in options) {
    throw new Error(
      'X-DNS-Prefetch-Control option was specified twice. Remove the `dnsPrefetchControl` option to fix this error.'
    )
  }
  const xDnsPrefetchControlOption =
      options.xDnsPrefetchControl ?? options.dnsPrefetchControl
  switch (xDnsPrefetchControlOption) {
    case undefined:
    case true:
      result.push(xDnsPrefetchControl())
      break
    case false:
      break
    default:
      result.push(xDnsPrefetchControl(xDnsPrefetchControlOption))
      break
  }

  if ('xDownloadOptions' in options && 'ieNoOpen' in options) {
    throw new Error(
      'X-Download-Options option was specified twice. Remove the `ieNoOpen` option to fix this error.'
    )
  }
  const xDownloadOptionsOption = options.xDownloadOptions ?? options.ieNoOpen
  switch (xDownloadOptionsOption) {
    case undefined:
    case true:
      result.push(xDownloadOptions())
      break
    case false:
      break
    default:
      console.warn(
        'X-Download-Options does not take options. Remove the property to silence this warning.'
      )
      result.push(xDownloadOptions())
      break
  }

  if ('xFrameOptions' in options && 'frameguard' in options) {
    throw new Error(
      'X-Frame-Options option was specified twice. Remove the `frameguard` option to fix this error.'
    )
  }
  const xFrameOptionsOption = options.xFrameOptions ?? options.frameguard
  switch (xFrameOptionsOption) {
    case undefined:
    case true:
      result.push(xFrameOptions())
      break
    case false:
      break
    default:
      result.push(xFrameOptions(xFrameOptionsOption))
      break
  }

  if (
    'xPermittedCrossDomainPolicies' in options &&
      'permittedCrossDomainPolicies' in options
  ) {
    throw new Error(
      'X-Permitted-Cross-Domain-Policies option was specified twice. Remove the `permittedCrossDomainPolicies` option to fix this error.'
    )
  }
  const xPermittedCrossDomainPoliciesOption =
      options.xPermittedCrossDomainPolicies ??
      options.permittedCrossDomainPolicies
  switch (xPermittedCrossDomainPoliciesOption) {
    case undefined:
    case true:
      result.push(xPermittedCrossDomainPolicies())
      break
    case false:
      break
    default:
      result.push(
        xPermittedCrossDomainPolicies(xPermittedCrossDomainPoliciesOption)
      )
      break
  }

  if ('xPoweredBy' in options && 'hidePoweredBy' in options) {
    throw new Error(
      'X-Powered-By option was specified twice. Remove the `hidePoweredBy` option to fix this error.'
    )
  }
  const xPoweredByOption = options.xPoweredBy ?? options.hidePoweredBy
  const xPoweredBy = function xPoweredBy () {
    return async function xPoweredByMiddleware (ctx: HoaContext, next: () => Promise<void>) {
      ctx.res.delete('X-Powered-By')
      await next()
    }
  }
  switch (xPoweredByOption) {
    case undefined:
    case true:
      result.push(xPoweredBy())
      break
    case false:
      break
    default:
      console.warn(
        'X-Powered-By does not take options. Remove the property to silence this warning.'
      )
      result.push(xPoweredBy())
      break
  }

  if ('xXssProtection' in options && 'xssFilter' in options) {
    throw new Error(
      'X-XSS-Protection option was specified twice. Remove the `xssFilter` option to fix this error.'
    )
  }
  const xXssProtectionOption = options.xXssProtection ?? options.xssFilter
  switch (xXssProtectionOption) {
    case undefined:
    case true:
      result.push(xXssProtection())
      break
    case false:
      break
    default:
      console.warn(
        'X-XSS-Protection does not take options. Remove the property to silence this warning.'
      )
      result.push(xXssProtection())
      break
  }

  if (options.permissionPolicy && typeof options.permissionPolicy === 'object') {
    result.push(permissionPolicy(options.permissionPolicy))
  }

  return result
}

export const secureHeaders: SecureHeaders = Object.assign(
  function secureHeaders (options: SecureHeadersOptions = {}): HoaMiddleware {
    const middlewareFunctions = getMiddlewareFunctionsFromOptions(options)

    const secureHeadersHandler = compose(middlewareFunctions)
    return async function secureHeadersMiddleware (ctx : HoaContext, next: () => Promise<void>) {
      await secureHeadersHandler(ctx, next)
    }
  },
  {
    contentSecurityPolicy,
    crossOriginEmbedderPolicy,
    crossOriginOpenerPolicy,
    crossOriginResourcePolicy,
    originAgentCluster,
    referrerPolicy,
    strictTransportSecurity,
    xContentTypeOptions,
    xDnsPrefetchControl,
    xDownloadOptions,
    xFrameOptions,
    xPermittedCrossDomainPolicies,
    xXssProtection,
    permissionPolicy,

    // Legacy aliases
    dnsPrefetchControl: xDnsPrefetchControl,
    xssFilter: xXssProtection,
    permittedCrossDomainPolicies: xPermittedCrossDomainPolicies,
    ieNoOpen: xDownloadOptions,
    noSniff: xContentTypeOptions,
    frameguard: xFrameOptions,
    hsts: strictTransportSecurity,
  }
)
export {
  contentSecurityPolicy,
  crossOriginEmbedderPolicy,
  crossOriginOpenerPolicy,
  crossOriginResourcePolicy,
  originAgentCluster,
  referrerPolicy,
  strictTransportSecurity,
  xContentTypeOptions,
  xDnsPrefetchControl,
  xDownloadOptions,
  xFrameOptions,
  xXssProtection,
  permissionPolicy,

  // Legacy aliases
  strictTransportSecurity as hsts,
  xContentTypeOptions as noSniff,
  xDnsPrefetchControl as dnsPrefetchControl,
  xDownloadOptions as ieNoOpen,
  xFrameOptions as frameguard,
  xPermittedCrossDomainPolicies,
  xPermittedCrossDomainPolicies as permittedCrossDomainPolicies,
  xXssProtection as xssFilter,
}
export default secureHeaders

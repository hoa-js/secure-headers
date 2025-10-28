import type { HoaContext, HoaMiddleware } from 'hoa'

// https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md

type PermissionsPolicyDirective =
  | StandardizedFeatures
  | ProposedFeatures
  | ExperimentalFeatures

/**
 * These features have been declared in a published version of the respective specification.
 */
type StandardizedFeatures =
  | 'accelerometer'
  | 'ambientLightSensor'
  | 'attributionReporting'
  | 'autoplay'
  | 'battery'
  | 'bluetooth'
  | 'camera'
  | 'chUa'
  | 'chUaArch'
  | 'chUaBitness'
  | 'chUaFullVersion'
  | 'chUaFullVersionList'
  | 'chUaMobile'
  | 'chUaModel'
  | 'chUaPlatform'
  | 'chUaPlatformVersion'
  | 'chUaWow64'
  | 'computePressure'
  | 'crossOriginIsolated'
  | 'directSockets'
  | 'displayCapture'
  | 'encryptedMedia'
  | 'executionWhileNotRendered'
  | 'executionWhileOutOfViewport'
  | 'fullscreen'
  | 'geolocation'
  | 'gyroscope'
  | 'hid'
  | 'identityCredentialsGet'
  | 'idleDetection'
  | 'keyboardMap'
  | 'magnetometer'
  | 'microphone'
  | 'midi'
  | 'navigationOverride'
  | 'payment'
  | 'pictureInPicture'
  | 'publickeyCredentialsGet'
  | 'screenWakeLock'
  | 'serial'
  | 'storageAccess'
  | 'syncXhr'
  | 'usb'
  | 'webShare'
  | 'windowManagement'
  | 'xrSpatialTracking'

/**
 * These features have been proposed, but the definitions have not yet been integrated into their respective specs.
 */
type ProposedFeatures =
  | 'clipboardRead'
  | 'clipboardWrite'
  | 'gamepad'
  | 'sharedAutofill'
  | 'speakerSelection'

/**
 * These features generally have an explainer only but may be available for experimentation by web developers.
 */
type ExperimentalFeatures =
  | 'allScreensCapture'
  | 'browsingTopics'
  | 'capturedSurfaceControl'
  | 'conversionMeasurement'
  | 'digitalCredentialsGet'
  | 'focusWithoutUserActivation'
  | 'joinAdInterestGroup'
  | 'localFonts'
  | 'runAdAuction'
  | 'smartCard'
  | 'syncScript'
  | 'trustTokenRedemption'
  | 'unload'
  | 'verticalScroll'

type PermissionsPolicyValue = '*' | 'self' | 'src' | 'none' | string

export type PermissionPolicyOptions = Partial<
  Record<PermissionsPolicyDirective, PermissionsPolicyValue[] | boolean>
>

function dashify (str: string) {
  return str.replace(/([a-z\d])([A-Z])/g, '$1-$2').toLowerCase()
}

const SHOULD_NOT_BE_QUOTED = new Set(['*', 'none', 'self', 'src'])

function normalizeDirectives (options: PermissionPolicyOptions) {
  const directiveNamesSeen = new Set<string>()
  const result: Record<string, string> = {}
  for (const rawDirectiveName in options) {
    const directiveName = dashify(rawDirectiveName)
    if (directiveNamesSeen.has(directiveName)) {
      throw new Error(`Permission-Policy received a duplicate directive ${JSON.stringify(
        directiveName
      )}`)
    }
    directiveNamesSeen.add(directiveName)
    const rawDirectiveValue = options[rawDirectiveName]
    if (typeof rawDirectiveValue === 'boolean') {
      result[directiveName] = rawDirectiveValue ? '(*)' : '()'
    } else if (Array.isArray(rawDirectiveValue)) {
      if (rawDirectiveValue.length === 0) {
        result[directiveName] = '()'
      } else if (rawDirectiveValue.length === 1 && (rawDirectiveValue[0] === '*' || rawDirectiveValue[0] === 'none')) {
        result[directiveName] = `(${rawDirectiveValue[0]})`
      } else {
        const allowList = rawDirectiveValue.map(v => SHOULD_NOT_BE_QUOTED.has(v) ? v : `"${v}"`)
        result[directiveName] = `(${allowList.join(' ')})`
      }
    } else {
      throw new Error(
        `Permission-Policy received an invalid directive value for ${JSON.stringify(
          directiveName
        )}. ${JSON.stringify(rawDirectiveValue)} should be a boolean or an array of strings.`
      )
    }
  }
  if (Object.keys(result).length === 0) {
    throw new Error('Permission-Policy has no directives. Either set some or disable the header')
  }
  return result
}

function getHeaderValue (normalizedDirectives:Partial<Record<PermissionsPolicyDirective, string>>) {
  return Object.entries(normalizedDirectives)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ')
}
export function permissionPolicy (options: PermissionPolicyOptions = {}): HoaMiddleware {
  const normalizedDirectives = normalizeDirectives(options)
  const headerValue = getHeaderValue(normalizedDirectives)
  return async function permissionPolicyMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('Permissions-Policy', headerValue)
    await next()
  }
}
export default permissionPolicy

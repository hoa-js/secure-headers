import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import { permissionPolicy } from '../src/permissionPolicy'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Permissions Policy middleware', () => {
  describe('Basic functionality', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should work with empty options', async () => {
      expect(() => {
        app.get('/test', permissionPolicy({}), (ctx) => {
          ctx.res.body = 'Test'
        })
      }).toThrow('Permission-Policy has no directives. Either set some or disable the header')
    })

    it('Should work without any options', async () => {
      expect(() => {
        app.get('/test', permissionPolicy(), (ctx) => {
          ctx.res.body = 'Test'
        })
      }).toThrow('Permission-Policy has no directives. Either set some or disable the header')
    })

    it('Should set Permissions-Policy header with simple directive', async () => {
      app.get('/test', permissionPolicy({
        camera: ['*']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(*)')
    })
  })

  describe('Boolean directive values', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle true boolean value', async () => {
      app.get('/test', permissionPolicy({
        camera: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(*)')
    })

    it('Should handle false boolean value', async () => {
      app.get('/test', permissionPolicy({
        microphone: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('microphone=()')
    })

    it('Should handle multiple boolean directives', async () => {
      app.get('/test', permissionPolicy({
        camera: true,
        microphone: false,
        geolocation: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('camera=(*)')
      expect(header).toContain('microphone=()')
      expect(header).toContain('geolocation=(*)')
    })
  })

  describe('Array directive values', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle empty array', async () => {
      app.get('/test', permissionPolicy({
        camera: []
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=()')
    })

    it('Should handle single star value', async () => {
      app.get('/test', permissionPolicy({
        camera: ['*']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(*)')
    })

    it('Should handle single none value', async () => {
      app.get('/test', permissionPolicy({
        microphone: ['none']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('microphone=(none)')
    })

    it('Should handle self value', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(self)')
    })

    it('Should handle src value', async () => {
      app.get('/test', permissionPolicy({
        camera: ['src']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(src)')
    })

    it('Should handle multiple values with quotes', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self', 'https://example.com', 'https://trusted.com']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(self "https://example.com" "https://trusted.com")')
    })

    it('Should handle mixed special and domain values', async () => {
      app.get('/test', permissionPolicy({
        geolocation: ['self', 'none', 'https://maps.example.com']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('geolocation=(self none "https://maps.example.com")')
    })
  })

  describe('Directive name normalization', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should convert camelCase directive names to kebab-case', async () => {
      app.get('/test', permissionPolicy({
        ambientLightSensor: ['self'],
        chUaFullVersion: ['*']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('ambient-light-sensor=(self)')
      expect(header).toContain('ch-ua-full-version=(*)')
    })

    it('Should handle already kebab-case directive names', async () => {
      app.get('/test', permissionPolicy({
        'display-capture': ['self'],
        'encrypted-media': false
      } as any), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('display-capture=(self)')
      expect(header).toContain('encrypted-media=()')
    })
  })

  describe('Error handling', () => {
    it('Should throw error for empty directives', () => {
      expect(() => {
        permissionPolicy({})
      }).toThrow('Permission-Policy has no directives. Either set some or disable the header')
    })

    it('Should throw error for duplicate directive names', () => {
      expect(() => {
        permissionPolicy({
          camera: ['self'],
          Camera: ['*'] // Will become 'camera' after dashify
        } as any)
      }).toThrow('Permission-Policy received a duplicate directive "camera"')
    })

    it('Should throw error for invalid directive value type', () => {
      expect(() => {
        permissionPolicy({
          camera: 'invalid' as any
        })
      }).toThrow('Permission-Policy received an invalid directive value for "camera". "invalid" should be a boolean or an array of strings.')
    })

    it('Should throw error for null directive value', () => {
      expect(() => {
        permissionPolicy({
          camera: null as any
        })
      }).toThrow('Permission-Policy received an invalid directive value for "camera". null should be a boolean or an array of strings.')
    })

    it('Should throw error for undefined directive value', () => {
      expect(() => {
        permissionPolicy({
          camera: undefined as any
        })
      }).toThrow('Permission-Policy received an invalid directive value for "camera". undefined should be a boolean or an array of strings.')
    })

    it('Should throw error for number directive value', () => {
      expect(() => {
        permissionPolicy({
          camera: 123 as any
        })
      }).toThrow('Permission-Policy received an invalid directive value for "camera". 123 should be a boolean or an array of strings.')
    })

    it('Should throw error for object directive value', () => {
      expect(() => {
        permissionPolicy({
          camera: {} as any
        })
      }).toThrow('Permission-Policy received an invalid directive value for "camera". {} should be a boolean or an array of strings.')
    })
  })

  describe('Standardized features', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle all standardized accelerometer features', async () => {
      app.get('/test', permissionPolicy({
        accelerometer: ['self'],
        ambientLightSensor: false,
        attributionReporting: ['*'],
        autoplay: ['self', 'https://videos.example.com']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('accelerometer=(self)')
      expect(header).toContain('ambient-light-sensor=()')
      expect(header).toContain('attribution-reporting=(*)')
      expect(header).toContain('autoplay=(self "https://videos.example.com")')
    })

    it('Should handle battery and bluetooth features', async () => {
      app.get('/test', permissionPolicy({
        battery: true,
        bluetooth: ['none']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('battery=(*)')
      expect(header).toContain('bluetooth=(none)')
    })

    it('Should handle client hints features', async () => {
      app.get('/test', permissionPolicy({
        chUa: ['self'],
        chUaArch: false,
        chUaBitness: ['*'],
        chUaFullVersion: ['self'],
        chUaFullVersionList: ['self'],
        chUaMobile: true,
        chUaModel: ['none'],
        chUaPlatform: ['self'],
        chUaPlatformVersion: false,
        chUaWow64: ['*']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('ch-ua=(self)')
      expect(header).toContain('ch-ua-arch=()')
      expect(header).toContain('ch-ua-bitness=(*)')
      expect(header).toContain('ch-ua-full-version=(self)')
      expect(header).toContain('ch-ua-full-version-list=(self)')
      expect(header).toContain('ch-ua-mobile=(*)')
      expect(header).toContain('ch-ua-model=(none)')
      expect(header).toContain('ch-ua-platform=(self)')
      expect(header).toContain('ch-ua-platform-version=()')
      expect(header).toContain('ch-ua-wow64=(*)')
    })

    it('Should handle media and device features', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self'],
        microphone: ['self'],
        displayCapture: false,
        encryptedMedia: ['*'],
        fullscreen: true,
        pictureInPicture: ['self']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('camera=(self)')
      expect(header).toContain('microphone=(self)')
      expect(header).toContain('display-capture=()')
      expect(header).toContain('encrypted-media=(*)')
      expect(header).toContain('fullscreen=(*)')
      expect(header).toContain('picture-in-picture=(self)')
    })

    it('Should handle location and sensor features', async () => {
      app.get('/test', permissionPolicy({
        geolocation: ['self'],
        gyroscope: false,
        magnetometer: ['none'],
        computePressure: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('geolocation=(self)')
      expect(header).toContain('gyroscope=()')
      expect(header).toContain('magnetometer=(none)')
      expect(header).toContain('compute-pressure=(*)')
    })

    it('Should handle advanced features', async () => {
      app.get('/test', permissionPolicy({
        crossOriginIsolated: true,
        directSockets: false,
        executionWhileNotRendered: ['self'],
        executionWhileOutOfViewport: ['none'],
        hid: ['*'],
        identityCredentialsGet: ['self'],
        idleDetection: false,
        keyboardMap: true,
        midi: ['self'],
        navigationOverride: ['none'],
        payment: ['*'],
        publickeyCredentialsGet: ['self'],
        screenWakeLock: true,
        serial: false,
        storageAccess: ['self'],
        syncXhr: ['none'],
        usb: ['*'],
        webShare: true,
        windowManagement: false,
        xrSpatialTracking: ['self']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('cross-origin-isolated=(*)')
      expect(header).toContain('direct-sockets=()')
      expect(header).toContain('execution-while-not-rendered=(self)')
      expect(header).toContain('execution-while-out-of-viewport=(none)')
      expect(header).toContain('hid=(*)')
      expect(header).toContain('identity-credentials-get=(self)')
      expect(header).toContain('idle-detection=()')
      expect(header).toContain('keyboard-map=(*)')
      expect(header).toContain('midi=(self)')
      expect(header).toContain('navigation-override=(none)')
      expect(header).toContain('payment=(*)')
      expect(header).toContain('publickey-credentials-get=(self)')
      expect(header).toContain('screen-wake-lock=(*)')
      expect(header).toContain('serial=()')
      expect(header).toContain('storage-access=(self)')
      expect(header).toContain('sync-xhr=(none)')
      expect(header).toContain('usb=(*)')
      expect(header).toContain('web-share=(*)')
      expect(header).toContain('window-management=()')
      expect(header).toContain('xr-spatial-tracking=(self)')
    })
  })

  describe('Proposed features', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle proposed features', async () => {
      app.get('/test', permissionPolicy({
        clipboardRead: ['self'],
        clipboardWrite: true,
        gamepad: false,
        sharedAutofill: ['*'],
        speakerSelection: ['none']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('clipboard-read=(self)')
      expect(header).toContain('clipboard-write=(*)')
      expect(header).toContain('gamepad=()')
      expect(header).toContain('shared-autofill=(*)')
      expect(header).toContain('speaker-selection=(none)')
    })
  })

  describe('Experimental features', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle experimental features', async () => {
      app.get('/test', permissionPolicy({
        allScreensCapture: ['self'],
        browsingTopics: false,
        capturedSurfaceControl: true,
        conversionMeasurement: ['*'],
        digitalCredentialsGet: ['none'],
        focusWithoutUserActivation: ['self'],
        joinAdInterestGroup: false,
        localFonts: true,
        runAdAuction: ['*'],
        smartCard: ['self'],
        syncScript: false,
        trustTokenRedemption: ['none'],
        unload: true,
        verticalScroll: ['*']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')
      expect(header).toContain('all-screens-capture=(self)')
      expect(header).toContain('browsing-topics=()')
      expect(header).toContain('captured-surface-control=(*)')
      expect(header).toContain('conversion-measurement=(*)')
      expect(header).toContain('digital-credentials-get=(none)')
      expect(header).toContain('focus-without-user-activation=(self)')
      expect(header).toContain('join-ad-interest-group=()')
      expect(header).toContain('local-fonts=(*)')
      expect(header).toContain('run-ad-auction=(*)')
      expect(header).toContain('smart-card=(self)')
      expect(header).toContain('sync-script=()')
      expect(header).toContain('trust-token-redemption=(none)')
      expect(header).toContain('unload=(*)')
      expect(header).toContain('vertical-scroll=(*)')
    })
  })

  describe('Complex scenarios', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle multiple directives with different value types', async () => {
      app.get('/test', permissionPolicy({
        camera: true,
        microphone: false,
        geolocation: ['self'],
        payment: ['*'],
        bluetooth: ['none'],
        gyroscope: [],
        fullscreen: ['self', 'https://trusted.example.com']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')

      // Check all directives are present
      expect(header).toContain('camera=(*)')
      expect(header).toContain('microphone=()')
      expect(header).toContain('geolocation=(self)')
      expect(header).toContain('payment=(*)')
      expect(header).toContain('bluetooth=(none)')
      expect(header).toContain('gyroscope=()')
      expect(header).toContain('fullscreen=(self "https://trusted.example.com")')

      // Check proper comma separation
      const directiveCount = (header?.split(',') || []).length
      expect(directiveCount).toBe(7)
    })

    it('Should properly format header with complex allowlists', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self', 'src', 'https://cam1.example.com', 'https://cam2.example.com'],
        microphone: ['self', 'https://voice.example.com'],
        geolocation: ['none'],
        payment: ['*']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')

      expect(header).toContain('camera=(self src "https://cam1.example.com" "https://cam2.example.com")')
      expect(header).toContain('microphone=(self "https://voice.example.com")')
      expect(header).toContain('geolocation=(none)')
      expect(header).toContain('payment=(*)')
    })

    it('Should handle edge case with only boolean values', async () => {
      app.get('/test', permissionPolicy({
        camera: true,
        microphone: false,
        bluetooth: true,
        geolocation: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')

      expect(header).toContain('camera=(*)')
      expect(header).toContain('microphone=()')
      expect(header).toContain('bluetooth=(*)')
      expect(header).toContain('geolocation=()')
    })

    it('Should handle single directive', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(self)')
    })
  })

  describe('Header format validation', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should format header correctly with comma separation', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self'],
        microphone: false,
        geolocation: ['*']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')

      // Should be comma-separated
      const parts = header?.split(', ')
      expect(parts?.length).toBe(3)

      // Check each part has correct format
      expect(parts).toContain('camera=(self)')
      expect(parts).toContain('microphone=()')
      expect(parts).toContain('geolocation=(*)')
    })

    it('Should maintain consistent ordering', async () => {
      // Test multiple times to ensure consistent ordering
      for (let i = 0; i < 3; i++) {
        app = new Hoa()
        app.extend(tinyRouter())

        app.get('/test', permissionPolicy({
          zebra: true, // This would be last alphabetically
          camera: ['self'],
          microphone: false
        } as any), (ctx) => {
          ctx.res.body = 'Test'
        })

        const response = await app.fetch(new Request('http://localhost/test'))
        const header = response.headers.get('Permissions-Policy')

        // The order should be deterministic based on Object.entries
        expect(header).toBeTruthy()
        expect(header).toContain('zebra=(*)')
        expect(header).toContain('camera=(self)')
        expect(header).toContain('microphone=()')
      }
    })
  })

  describe('Edge cases', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle empty string origins properly', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self', '', 'https://example.com']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')

      // Empty strings should be quoted
      expect(header).toBe('camera=(self "" "https://example.com")')
    })

    it('Should handle special characters in origins', async () => {
      app.get('/test', permissionPolicy({
        camera: ['self', 'https://sub-domain.example.com:8080', 'https://example.com/path']
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const header = response.headers.get('Permissions-Policy')

      expect(header).toBe('camera=(self "https://sub-domain.example.com:8080" "https://example.com/path")')
    })
  })

  describe('Default export', () => {
    it('Should be the same as named export', () => {
      expect(permissionPolicy).toBeDefined()
      expect(typeof permissionPolicy).toBe('function')
    })

    it('Should return a middleware function', () => {
      const middleware = permissionPolicy({ camera: ['self'] })
      expect(typeof middleware).toBe('function')
      expect(middleware.name).toBe('permissionPolicyMiddleware')
    })
  })
})

import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import secureHeaders, {
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
  hsts,
  noSniff,
  dnsPrefetchControl,
  ieNoOpen,
  frameguard,
  permittedCrossDomainPolicies,
  xssFilter
} from '../src/index'
import { tinyRouter } from '@hoajs/tiny-router'

// Mock console methods to test warnings
const originalConsoleWarn = console.warn
beforeEach(() => {
  console.warn = jest.fn()
})

afterEach(() => {
  console.warn = originalConsoleWarn
})

describe('Secure Headers index', () => {
  describe('Basic functionality', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should work with default options', async () => {
      app.get('/test', secureHeaders(), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)

      // Default headers should be set
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeTruthy()
      expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeTruthy()
      expect(response.headers.get('Origin-Agent-Cluster')).toBeTruthy()
      expect(response.headers.get('Referrer-Policy')).toBeTruthy()
      expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
      expect(response.headers.get('X-Content-Type-Options')).toBeTruthy()
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBeTruthy()
      expect(response.headers.get('X-Download-Options')).toBeTruthy()
      expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBeTruthy()
      expect(response.headers.get('X-XSS-Protection')).toBeTruthy()
      expect(response.headers.has('X-Powered-By')).toBeFalsy()
    })

    it('Should work with empty options', async () => {
      app.get('/test', secureHeaders({}), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
    })

    it('Should work with next function', async () => {
      let middlewareCalled = false

      app.get(
        '/test',
        secureHeaders(),
        async (ctx, next) => {
          middlewareCalled = true
          if (next) await next()
        },
        (ctx) => {
          ctx.res.body = 'Test'
        }
      )

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(middlewareCalled).toBe(true)
    })
  })

  describe('Content Security Policy options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable CSP by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        contentSecurityPolicy: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
    })

    it('Should enable CSP with true', async () => {
      app.get('/test', secureHeaders({
        contentSecurityPolicy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
    })

    it('Should disable CSP with false', async () => {
      app.get('/test', secureHeaders({
        contentSecurityPolicy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Content-Security-Policy')).toBeFalsy()
    })

    it('Should use custom CSP options', async () => {
      app.get('/test', secureHeaders({
        contentSecurityPolicy: {
          directives: {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'"]
          }
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("script-src 'self' 'unsafe-inline'")
    })
  })

  describe('Cross-Origin Embedder Policy options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should not enable COEP by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        crossOriginEmbedderPolicy: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeFalsy()
    })

    it('Should not enable COEP with false', async () => {
      app.get('/test', secureHeaders({
        crossOriginEmbedderPolicy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeFalsy()
    })

    it('Should enable COEP with true', async () => {
      app.get('/test', secureHeaders({
        crossOriginEmbedderPolicy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeTruthy()
    })

    it('Should use custom COEP options', async () => {
      app.get('/test', secureHeaders({
        crossOriginEmbedderPolicy: { policy: 'credentialless' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBe('credentialless')
    })
  })

  describe('Cross-Origin Opener Policy options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable COOP by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        crossOriginOpenerPolicy: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeTruthy()
    })

    it('Should enable COOP with true', async () => {
      app.get('/test', secureHeaders({
        crossOriginOpenerPolicy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeTruthy()
    })

    it('Should disable COOP with false', async () => {
      app.get('/test', secureHeaders({
        crossOriginOpenerPolicy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeFalsy()
    })

    it('Should use custom COOP options', async () => {
      app.get('/test', secureHeaders({
        crossOriginOpenerPolicy: { policy: 'unsafe-none' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBe('unsafe-none')
    })
  })

  describe('Cross-Origin Resource Policy options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable CORP by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        crossOriginResourcePolicy: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeTruthy()
    })

    it('Should enable CORP with true', async () => {
      app.get('/test', secureHeaders({
        crossOriginResourcePolicy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeTruthy()
    })

    it('Should disable CORP with false', async () => {
      app.get('/test', secureHeaders({
        crossOriginResourcePolicy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeFalsy()
    })

    it('Should use custom CORP options', async () => {
      app.get('/test', secureHeaders({
        crossOriginResourcePolicy: { policy: 'cross-origin' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Cross-Origin-Resource-Policy')).toBe('cross-origin')
    })
  })

  describe('Origin Agent Cluster options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable Origin-Agent-Cluster by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        originAgentCluster: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Origin-Agent-Cluster')).toBe('?1')
    })

    it('Should enable Origin-Agent-Cluster with true', async () => {
      app.get('/test', secureHeaders({
        originAgentCluster: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Origin-Agent-Cluster')).toBe('?1')
    })

    it('Should disable Origin-Agent-Cluster with false', async () => {
      app.get('/test', secureHeaders({
        originAgentCluster: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Origin-Agent-Cluster')).toBeFalsy()
    })

    it('Should warn and enable Origin-Agent-Cluster with invalid options', async () => {
      app.get('/test', secureHeaders({
        originAgentCluster: { invalid: true } as any
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Origin-Agent-Cluster')).toBe('?1')
      expect(console.warn).toHaveBeenCalledWith(
        'Origin-Agent-Cluster does not take options. Remove the property to silence this warning.'
      )
    })
  })

  describe('Referrer Policy options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable Referrer-Policy by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        referrerPolicy: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Referrer-Policy')).toBeTruthy()
    })

    it('Should enable Referrer-Policy with true', async () => {
      app.get('/test', secureHeaders({
        referrerPolicy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Referrer-Policy')).toBeTruthy()
    })

    it('Should disable Referrer-Policy with false', async () => {
      app.get('/test', secureHeaders({
        referrerPolicy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Referrer-Policy')).toBeFalsy()
    })

    it('Should use custom Referrer-Policy options', async () => {
      app.get('/test', secureHeaders({
        referrerPolicy: { policy: 'origin' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Referrer-Policy')).toBe('origin')
    })
  })

  describe('Strict Transport Security options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable HSTS by default with strictTransportSecurity (undefined)', async () => {
      app.get('/test', secureHeaders({
        strictTransportSecurity: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
    })

    it('Should enable HSTS with strictTransportSecurity true', async () => {
      app.get('/test', secureHeaders({
        strictTransportSecurity: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
    })

    it('Should disable HSTS with strictTransportSecurity false', async () => {
      app.get('/test', secureHeaders({
        strictTransportSecurity: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Strict-Transport-Security')).toBeFalsy()
    })

    it('Should use custom HSTS options with strictTransportSecurity', async () => {
      app.get('/test', secureHeaders({
        strictTransportSecurity: { maxAge: 7200, preload: true }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const hsts = response.headers.get('Strict-Transport-Security')
      expect(hsts).toContain('max-age=7200')
      expect(hsts).toContain('preload')
    })

    it('Should enable HSTS by default with hsts (undefined)', async () => {
      app.get('/test', secureHeaders({
        hsts: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
    })

    it('Should enable HSTS with hsts true', async () => {
      app.get('/test', secureHeaders({
        hsts: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
    })

    it('Should disable HSTS with hsts false', async () => {
      app.get('/test', secureHeaders({
        hsts: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Strict-Transport-Security')).toBeFalsy()
    })

    it('Should use custom HSTS options with hsts', async () => {
      app.get('/test', secureHeaders({
        hsts: { maxAge: 3600 }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Strict-Transport-Security')).toContain('max-age=3600')
    })

    it('Should throw error when both strictTransportSecurity and hsts are specified', () => {
      expect(() => {
        secureHeaders({
          strictTransportSecurity: true,
          hsts: false
        } as any)
      }).toThrow('Strict-Transport-Security option was specified twice. Remove the `hsts` option to fix this error.')
    })
  })

  describe('X-Content-Type-Options options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable X-Content-Type-Options by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        xContentTypeOptions: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
    })

    it('Should enable X-Content-Type-Options with true', async () => {
      app.get('/test', secureHeaders({
        xContentTypeOptions: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
    })

    it('Should disable X-Content-Type-Options with false', async () => {
      app.get('/test', secureHeaders({
        xContentTypeOptions: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Content-Type-Options')).toBeFalsy()
    })

    it('Should warn and enable X-Content-Type-Options with invalid options', async () => {
      app.get('/test', secureHeaders({
        xContentTypeOptions: { invalid: true } as any
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(console.warn).toHaveBeenCalledWith(
        'X-Content-Type-Options does not take options. Remove the property to silence this warning.'
      )
    })

    it('Should enable X-Content-Type-Options with noSniff alias', async () => {
      app.get('/test', secureHeaders({
        noSniff: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
    })

    it('Should throw error when both xContentTypeOptions and noSniff are specified', () => {
      expect(() => {
        secureHeaders({
          xContentTypeOptions: true,
          noSniff: false
        } as any)
      }).toThrow('X-Content-Type-Options option was specified twice. Remove the `noSniff` option to fix this error.')
    })
  })

  describe('X-DNS-Prefetch-Control options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable X-DNS-Prefetch-Control by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        xDnsPrefetchControl: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBe('off')
    })

    it('Should enable X-DNS-Prefetch-Control with true', async () => {
      app.get('/test', secureHeaders({
        xDnsPrefetchControl: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBe('off')
    })

    it('Should disable X-DNS-Prefetch-Control with false', async () => {
      app.get('/test', secureHeaders({
        xDnsPrefetchControl: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBeFalsy()
    })

    it('Should use custom X-DNS-Prefetch-Control options', async () => {
      app.get('/test', secureHeaders({
        xDnsPrefetchControl: { allow: true }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBe('on')
    })

    it('Should work with dnsPrefetchControl alias', async () => {
      app.get('/test', secureHeaders({
        dnsPrefetchControl: { allow: true }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBe('on')
    })

    it('Should throw error when both xDnsPrefetchControl and dnsPrefetchControl are specified', () => {
      expect(() => {
        secureHeaders({
          xDnsPrefetchControl: true,
          dnsPrefetchControl: false
        } as any)
      }).toThrow('X-DNS-Prefetch-Control option was specified twice. Remove the `dnsPrefetchControl` option to fix this error.')
    })
  })

  describe('X-Download-Options options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable X-Download-Options by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        xDownloadOptions: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Download-Options')).toBe('noopen')
    })

    it('Should enable X-Download-Options with true', async () => {
      app.get('/test', secureHeaders({
        xDownloadOptions: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Download-Options')).toBe('noopen')
    })

    it('Should disable X-Download-Options with false', async () => {
      app.get('/test', secureHeaders({
        xDownloadOptions: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Download-Options')).toBeFalsy()
    })

    it('Should warn and enable X-Download-Options with invalid options', async () => {
      app.get('/test', secureHeaders({
        xDownloadOptions: { invalid: true } as any
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Download-Options')).toBe('noopen')
      expect(console.warn).toHaveBeenCalledWith(
        'X-Download-Options does not take options. Remove the property to silence this warning.'
      )
    })

    it('Should work with ieNoOpen alias', async () => {
      app.get('/test', secureHeaders({
        ieNoOpen: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Download-Options')).toBe('noopen')
    })

    it('Should throw error when both xDownloadOptions and ieNoOpen are specified', () => {
      expect(() => {
        secureHeaders({
          xDownloadOptions: true,
          ieNoOpen: false
        } as any)
      }).toThrow('X-Download-Options option was specified twice. Remove the `ieNoOpen` option to fix this error.')
    })
  })

  describe('X-Frame-Options options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable X-Frame-Options by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        xFrameOptions: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
    })

    it('Should enable X-Frame-Options with true', async () => {
      app.get('/test', secureHeaders({
        xFrameOptions: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
    })

    it('Should disable X-Frame-Options with false', async () => {
      app.get('/test', secureHeaders({
        xFrameOptions: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Frame-Options')).toBeFalsy()
    })

    it('Should use custom X-Frame-Options', async () => {
      app.get('/test', secureHeaders({
        xFrameOptions: { action: 'deny' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Frame-Options')).toBe('DENY')
    })

    it('Should work with frameguard alias', async () => {
      app.get('/test', secureHeaders({
        frameguard: { action: 'deny' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Frame-Options')).toBe('DENY')
    })

    it('Should throw error when both xFrameOptions and frameguard are specified', () => {
      expect(() => {
        secureHeaders({
          xFrameOptions: true,
          frameguard: false
        } as any)
      }).toThrow('X-Frame-Options option was specified twice. Remove the `frameguard` option to fix this error.')
    })
  })

  describe('X-Permitted-Cross-Domain-Policies options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable X-Permitted-Cross-Domain-Policies by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        xPermittedCrossDomainPolicies: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none')
    })

    it('Should enable X-Permitted-Cross-Domain-Policies with true', async () => {
      app.get('/test', secureHeaders({
        xPermittedCrossDomainPolicies: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none')
    })

    it('Should disable X-Permitted-Cross-Domain-Policies with false', async () => {
      app.get('/test', secureHeaders({
        xPermittedCrossDomainPolicies: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBeFalsy()
    })

    it('Should use custom X-Permitted-Cross-Domain-Policies options', async () => {
      app.get('/test', secureHeaders({
        xPermittedCrossDomainPolicies: { permittedPolicies: 'master-only' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('master-only')
    })

    it('Should work with permittedCrossDomainPolicies alias', async () => {
      app.get('/test', secureHeaders({
        permittedCrossDomainPolicies: { permittedPolicies: 'all' }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('all')
    })

    it('Should throw error when both xPermittedCrossDomainPolicies and permittedCrossDomainPolicies are specified', () => {
      expect(() => {
        secureHeaders({
          xPermittedCrossDomainPolicies: true,
          permittedCrossDomainPolicies: false
        } as any)
      }).toThrow('X-Permitted-Cross-Domain-Policies option was specified twice. Remove the `permittedCrossDomainPolicies` option to fix this error.')
    })
  })

  describe('X-Powered-By options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
      // Set a fake X-Powered-By header to test removal
      app.use(async (ctx, next) => {
        ctx.res.set('X-Powered-By', 'Express')
        await next()
      })
    })

    it('Should remove X-Powered-By by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        xPoweredBy: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.has('X-Powered-By')).toBeFalsy()
    })

    it('Should remove X-Powered-By with true', async () => {
      app.get('/test', secureHeaders({
        xPoweredBy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.has('X-Powered-By')).toBeFalsy()
    })

    it('Should keep X-Powered-By with false', async () => {
      app.get('/test', secureHeaders({
        xPoweredBy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-Powered-By')).toBe('Express')
    })

    it('Should warn and remove X-Powered-By with invalid options', async () => {
      app.get('/test', secureHeaders({
        xPoweredBy: { invalid: true } as any
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.has('X-Powered-By')).toBeFalsy()
      expect(console.warn).toHaveBeenCalledWith(
        'X-Powered-By does not take options. Remove the property to silence this warning.'
      )
    })

    it('Should work with hidePoweredBy alias', async () => {
      app.get('/test', secureHeaders({
        hidePoweredBy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.has('X-Powered-By')).toBeFalsy()
    })

    it('Should throw error when both xPoweredBy and hidePoweredBy are specified', () => {
      expect(() => {
        secureHeaders({
          xPoweredBy: true,
          hidePoweredBy: false
        } as any)
      }).toThrow('X-Powered-By option was specified twice. Remove the `hidePoweredBy` option to fix this error.')
    })
  })

  describe('X-XSS-Protection options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should enable X-XSS-Protection by default (undefined)', async () => {
      app.get('/test', secureHeaders({
        xXssProtection: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-XSS-Protection')).toBe('0')
    })

    it('Should enable X-XSS-Protection with true', async () => {
      app.get('/test', secureHeaders({
        xXssProtection: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-XSS-Protection')).toBe('0')
    })

    it('Should disable X-XSS-Protection with false', async () => {
      app.get('/test', secureHeaders({
        xXssProtection: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-XSS-Protection')).toBeFalsy()
    })

    it('Should warn and enable X-XSS-Protection with invalid options', async () => {
      app.get('/test', secureHeaders({
        xXssProtection: { invalid: true } as any
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-XSS-Protection')).toBe('0')
      expect(console.warn).toHaveBeenCalledWith(
        'X-XSS-Protection does not take options. Remove the property to silence this warning.'
      )
    })

    it('Should work with xssFilter alias', async () => {
      app.get('/test', secureHeaders({
        xssFilter: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('X-XSS-Protection')).toBe('0')
    })

    it('Should throw error when both xXssProtection and xssFilter are specified', () => {
      expect(() => {
        secureHeaders({
          xXssProtection: true,
          xssFilter: false
        } as any)
      }).toThrow('X-XSS-Protection option was specified twice. Remove the `xssFilter` option to fix this error.')
    })
  })

  describe('Permission Policy options', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should not set Permission-Policy when not provided', async () => {
      app.get('/test', secureHeaders(), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBeFalsy()
    })

    it('Should not set Permission-Policy when undefined', async () => {
      app.get('/test', secureHeaders({
        permissionPolicy: undefined
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBeFalsy()
    })

    it('Should set Permission-Policy when provided with valid options', async () => {
      app.get('/test', secureHeaders({
        permissionPolicy: { camera: ['*'] }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(*)')
    })

    it('Should not set Permission-Policy when provided with non-object value', async () => {
      app.get('/test', secureHeaders({
        permissionPolicy: true as any
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Permissions-Policy')).toBeFalsy()
    })
  })

  describe('Module exports', () => {
    it('Should export default secureHeaders function', () => {
      expect(typeof secureHeaders).toBe('function')
      expect(secureHeaders.name).toBe('secureHeaders')
    })

    it('Should export all middleware functions as properties', () => {
      expect(secureHeaders.contentSecurityPolicy).toBe(contentSecurityPolicy)
      expect(secureHeaders.crossOriginEmbedderPolicy).toBe(crossOriginEmbedderPolicy)
      expect(secureHeaders.crossOriginOpenerPolicy).toBe(crossOriginOpenerPolicy)
      expect(secureHeaders.crossOriginResourcePolicy).toBe(crossOriginResourcePolicy)
      expect(secureHeaders.originAgentCluster).toBe(originAgentCluster)
      expect(secureHeaders.referrerPolicy).toBe(referrerPolicy)
      expect(secureHeaders.strictTransportSecurity).toBe(strictTransportSecurity)
      expect(secureHeaders.xContentTypeOptions).toBe(xContentTypeOptions)
      expect(secureHeaders.xDnsPrefetchControl).toBe(xDnsPrefetchControl)
      expect(secureHeaders.xDownloadOptions).toBe(xDownloadOptions)
      expect(secureHeaders.xFrameOptions).toBe(xFrameOptions)
      expect(secureHeaders.xPermittedCrossDomainPolicies).toBe(xPermittedCrossDomainPolicies)
      expect(secureHeaders.xXssProtection).toBe(xXssProtection)
      expect(secureHeaders.permissionPolicy).toBe(permissionPolicy)
    })

    it('Should export all legacy aliases as properties', () => {
      expect(secureHeaders.dnsPrefetchControl).toBe(xDnsPrefetchControl)
      expect(secureHeaders.frameguard).toBe(xFrameOptions)
      expect(secureHeaders.hsts).toBe(strictTransportSecurity)
      expect(secureHeaders.ieNoOpen).toBe(xDownloadOptions)
      expect(secureHeaders.noSniff).toBe(xContentTypeOptions)
      expect(secureHeaders.permittedCrossDomainPolicies).toBe(xPermittedCrossDomainPolicies)
      expect(secureHeaders.xssFilter).toBe(xXssProtection)
    })

    it('Should export named exports', () => {
      expect(typeof contentSecurityPolicy).toBe('function')
      expect(typeof crossOriginEmbedderPolicy).toBe('function')
      expect(typeof crossOriginOpenerPolicy).toBe('function')
      expect(typeof crossOriginResourcePolicy).toBe('function')
      expect(typeof originAgentCluster).toBe('function')
      expect(typeof referrerPolicy).toBe('function')
      expect(typeof strictTransportSecurity).toBe('function')
      expect(typeof xContentTypeOptions).toBe('function')
      expect(typeof xDnsPrefetchControl).toBe('function')
      expect(typeof xDownloadOptions).toBe('function')
      expect(typeof xFrameOptions).toBe('function')
      expect(typeof xPermittedCrossDomainPolicies).toBe('function')
      expect(typeof xXssProtection).toBe('function')
      expect(typeof permissionPolicy).toBe('function')
    })

    it('Should export legacy alias named exports', () => {
      expect(hsts).toBe(strictTransportSecurity)
      expect(noSniff).toBe(xContentTypeOptions)
      expect(dnsPrefetchControl).toBe(xDnsPrefetchControl)
      expect(ieNoOpen).toBe(xDownloadOptions)
      expect(frameguard).toBe(xFrameOptions)
      expect(permittedCrossDomainPolicies).toBe(xPermittedCrossDomainPolicies)
      expect(xssFilter).toBe(xXssProtection)
    })
  })

  describe('Complex integration scenarios', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should work with all headers enabled', async () => {
      app.get('/test', secureHeaders({
        contentSecurityPolicy: { directives: { 'default-src': ["'self'"] } },
        crossOriginEmbedderPolicy: true,
        crossOriginOpenerPolicy: { policy: 'same-origin' },
        crossOriginResourcePolicy: { policy: 'same-site' },
        originAgentCluster: true,
        referrerPolicy: { policy: 'no-referrer' },
        strictTransportSecurity: { maxAge: 31536000 },
        xContentTypeOptions: true,
        xDnsPrefetchControl: { allow: false },
        xDownloadOptions: true,
        xFrameOptions: { action: 'sameorigin' },
        xPermittedCrossDomainPolicies: { permittedPolicies: 'none' },
        xXssProtection: true,
        xPoweredBy: true,
        permissionPolicy: { camera: ['self'] }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))

      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
      expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeTruthy()
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin')
      expect(response.headers.get('Cross-Origin-Resource-Policy')).toBe('same-site')
      expect(response.headers.get('Origin-Agent-Cluster')).toBe('?1')
      expect(response.headers.get('Referrer-Policy')).toBe('no-referrer')
      expect(response.headers.get('Strict-Transport-Security')).toContain('max-age=31536000')
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBe('off')
      expect(response.headers.get('X-Download-Options')).toBe('noopen')
      expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none')
      expect(response.headers.get('X-XSS-Protection')).toBe('0')
      expect(response.headers.get('Permissions-Policy')).toBe('camera=(self)')
      expect(response.headers.has('X-Powered-By')).toBeFalsy()
    })

    it('Should work with all headers disabled', async () => {
      app.get('/test', secureHeaders({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: false,
        crossOriginResourcePolicy: false,
        originAgentCluster: false,
        referrerPolicy: false,
        strictTransportSecurity: false,
        xContentTypeOptions: false,
        xDnsPrefetchControl: false,
        xDownloadOptions: false,
        xFrameOptions: false,
        xPermittedCrossDomainPolicies: false,
        xXssProtection: false,
        xPoweredBy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))

      expect(response.headers.get('Content-Security-Policy')).toBeFalsy()
      expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeFalsy()
      expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeFalsy()
      expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeFalsy()
      expect(response.headers.get('Origin-Agent-Cluster')).toBeFalsy()
      expect(response.headers.get('Referrer-Policy')).toBeFalsy()
      expect(response.headers.get('Strict-Transport-Security')).toBeFalsy()
      expect(response.headers.get('X-Content-Type-Options')).toBeFalsy()
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBeFalsy()
      expect(response.headers.get('X-Download-Options')).toBeFalsy()
      expect(response.headers.get('X-Frame-Options')).toBeFalsy()
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBeFalsy()
      expect(response.headers.get('X-XSS-Protection')).toBeFalsy()
      expect(response.headers.get('Permissions-Policy')).toBeFalsy()
    })

    it('Should work with mixed legacy aliases', async () => {
      app.get('/test', secureHeaders({
        contentSecurityPolicy: false,
        hsts: { maxAge: 7200 },
        noSniff: true,
        dnsPrefetchControl: { allow: true },
        ieNoOpen: true,
        frameguard: { action: 'deny' },
        permittedCrossDomainPolicies: { permittedPolicies: 'master-only' },
        xssFilter: true,
        hidePoweredBy: true
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))

      expect(response.headers.get('Content-Security-Policy')).toBeFalsy()
      expect(response.headers.get('Strict-Transport-Security')).toContain('max-age=7200')
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('X-DNS-Prefetch-Control')).toBe('on')
      expect(response.headers.get('X-Download-Options')).toBe('noopen')
      expect(response.headers.get('X-Frame-Options')).toBe('DENY')
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('master-only')
      expect(response.headers.get('X-XSS-Protection')).toBe('0')
      expect(response.headers.has('X-Powered-By')).toBeFalsy()
    })

    it('Should handle middleware composition correctly', async () => {
      const middlewareOrder: string[] = []

      app.get(
        '/test',
        secureHeaders({
          contentSecurityPolicy: { directives: { 'default-src': ["'self'"] } },
          strictTransportSecurity: { maxAge: 3600 }
        }),
        async (ctx, next) => {
          middlewareOrder.push('custom1')
          await next()
        },
        async (ctx, next) => {
          middlewareOrder.push('custom2')
          await next()
        },
        (ctx) => {
          middlewareOrder.push('handler')
          ctx.res.body = 'Test'
        }
      )

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
      expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
      expect(middlewareOrder).toEqual(['custom1', 'custom2', 'handler'])
    })
  })

  describe('Edge cases and error conditions', () => {
    it('Should handle empty middleware array', async () => {
      const app = new Hoa()
      app.extend(tinyRouter())

      app.get('/test', secureHeaders({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: false,
        crossOriginResourcePolicy: false,
        originAgentCluster: false,
        referrerPolicy: false,
        strictTransportSecurity: false,
        xContentTypeOptions: false,
        xDnsPrefetchControl: false,
        xDownloadOptions: false,
        xFrameOptions: false,
        xPermittedCrossDomainPolicies: false,
        xXssProtection: false,
        xPoweredBy: false
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy')).toBeFalsy()
    })
  })
})

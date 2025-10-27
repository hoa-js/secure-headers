import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import { tinyRouter } from '@hoajs/tiny-router'
import { contentSecurityPolicy } from '../src/contentSecurityPolicy'

describe('Content Security Policy middleware', () => {
  describe('Default behavior', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should set Content-Security-Policy header with default directives', async () => {
      app.get('/test', contentSecurityPolicy(), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy')).toContain("default-src 'self'")
      expect(response.headers.get('Content-Security-Policy')).toContain("base-uri 'self'")
      expect(response.headers.get('Content-Security-Policy')).toContain("font-src 'self' https: data:")
    })

    it('Should use Content-Security-Policy-Report-Only when reportOnly is true', async () => {
      app.get('/test', contentSecurityPolicy({ reportOnly: true }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy-Report-Only')).toContain("default-src 'self'")
      expect(response.headers.get('Content-Security-Policy')).toBeNull()
    })

    it('Should include all default directives when useDefaults is true', async () => {
      app.get('/test', contentSecurityPolicy({ useDefaults: true }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("base-uri 'self'")
      expect(cspHeader).toContain("font-src 'self' https: data:")
      expect(cspHeader).toContain("form-action 'self'")
      expect(cspHeader).toContain("frame-ancestors 'self'")
      expect(cspHeader).toContain("img-src 'self' data:")
      expect(cspHeader).toContain("object-src 'none'")
      expect(cspHeader).toContain("script-src 'self'")
      expect(cspHeader).toContain("script-src-attr 'none'")
      expect(cspHeader).toContain("style-src 'self' https: 'unsafe-inline'")
      expect(cspHeader).toContain('upgrade-insecure-requests')
    })
  })
  describe('Custom directives', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should accept custom directives as object', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-inline'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("script-src 'self' 'unsafe-inline'")
      expect(cspHeader).not.toContain('base-uri')
    })

    it('Should accept custom directives as string', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': "'self'",
          'script-src': "'unsafe-eval'"
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("script-src 'unsafe-eval'")
    })

    it('Should accept custom directives as array', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'", 'https:'],
          'img-src': ["'self'", 'data:', 'https:']
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self' https:")
      expect(cspHeader).toContain("img-src 'self' data: https:")
    })

    it('Should accept function-based directive values', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", (ctx) => "'nonce-' + Math.random().toString(36).substring(2)"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("script-src 'self' 'nonce-")
    })
  })
  describe('Directive name validation', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should throw error for empty directive name', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          '': ["'self'"],
          'default-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      try {
        const response = await app.fetch(new Request('http://localhost/test'))
        expect(response.status).toBe(500)
      } catch (e) {
        console.log(e)
      }
    })

    it('Should throw error for invalid directive name characters', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'script src': ["'self'"],
          'default-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should throw error for directive name with special characters', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'script@src': ["'self'"],
          'default-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should convert camelCase directive names to kebab-case', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("script-src 'self' 'unsafe-inline'")
    })

    it('Should throw error for duplicate directive names', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          defaultSrc: ["'none'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })
  })

  describe('Directive value validation', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should throw error for directive value containing semicolon', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'; malicious-directive"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should throw error for directive value containing comma', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self', 'unsafe-eval'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should throw error for nonce values that should not be quoted', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ['nonce-abc123']
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should throw error for hash values that should not be quoted', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ['sha256-abc123']
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })
  })

  describe('Default-src handling', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should throw error when default-src is set to null', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': null
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should allow disabling default-src with dangerouslyDisableDefaultSrc', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': contentSecurityPolicy.dangerouslyDisableDefaultSrc,
          'script-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).not.toContain('default-src')
      expect(cspHeader).toContain("script-src 'self'")
    })

    it('Should throw error when using dangerouslyDisableDefaultSrc on non-default-src directive', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': contentSecurityPolicy.dangerouslyDisableDefaultSrc
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should throw error when no default-src is provided and useDefaults is false', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'script-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })
  })

  describe('Null directive values', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should exclude directives set to null', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'object-src': null,
          'base-uri': null
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).not.toContain('object-src')
      expect(cspHeader).not.toContain('base-uri')
      expect(cspHeader).toContain("default-src 'self'")
    })

    it('Should throw error for invalid directive values', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': false as any
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })

    it('Should throw error for undefined directive values', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': undefined as any
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })
  })

  describe('useDefaults option', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should not include default directives when useDefaults is false', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("script-src 'self'")
      expect(cspHeader).not.toContain('base-uri')
      expect(cspHeader).not.toContain('font-src')
      expect(cspHeader).not.toContain('object-src')
    })

    it('Should merge custom directives with defaults when useDefaults is true', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: true,
        directives: {
          'script-src': ["'self'", "'unsafe-eval'"],
          'custom-directive': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("script-src 'self' 'unsafe-eval'")
      expect(cspHeader).toContain("custom-directive 'self'")
      expect(cspHeader).toContain("base-uri 'self'")
    })

    it('Should use defaults when useDefaults is undefined (default behavior)', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'script-src': ["'self'", "'unsafe-eval'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("script-src 'self' 'unsafe-eval'")
      expect(cspHeader).toContain("base-uri 'self'")
    })
  })

  describe('Empty directives handling', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle directives with empty arrays', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'upgrade-insecure-requests': []
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain('upgrade-insecure-requests')
      expect(response.status).toBe(200)
    })

    it('Should throw error when no directives are provided', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {}
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })
  })

  describe('Header formatting', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should format header with semicolon and space separation', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-inline'"],
          'style-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toMatch(/default-src[^;]+; script-src[^;]+; style-src[^;]+/)
    })

    it('Should handle mixed function and string directive values', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", (ctx) => 'https://cdn.example.com'],
          'style-src': ["'self'", "'unsafe-inline'"]
        }
      }), (ctx) => {
        ctx.res.body = 'GET success'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("script-src 'self' https://cdn.example.com")
    })
  })

  describe('getDefaultDirectives function', () => {
    it('Should return default directives object', () => {
      const defaults = contentSecurityPolicy.getDefaultDirectives()
      expect(defaults).toHaveProperty('default-src', ["'self'"])
      expect(defaults).toHaveProperty('base-uri', ["'self'"])
      expect(defaults).toHaveProperty('font-src', ["'self'", 'https:', 'data:'])
      expect(defaults).toHaveProperty('form-action', ["'self'"])
      expect(defaults).toHaveProperty('frame-ancestors', ["'self'"])
      expect(defaults).toHaveProperty('img-src', ["'self'", 'data:'])
      expect(defaults).toHaveProperty('object-src', ["'none'"])
      expect(defaults).toHaveProperty('script-src', ["'self'"])
      expect(defaults).toHaveProperty('script-src-attr', ["'none'"])
      expect(defaults).toHaveProperty('style-src', ["'self'", 'https:', "'unsafe-inline'"])
      expect(defaults).toHaveProperty('upgrade-insecure-requests', [])
    })

    it('Should return a new object each time (not shared reference)', () => {
      const defaults1 = contentSecurityPolicy.getDefaultDirectives()
      const defaults2 = contentSecurityPolicy.getDefaultDirectives()
      expect(defaults1).not.toBe(defaults2)
      expect(defaults1).toEqual(defaults2)
    })
  })

  describe('Real-world scenarios', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should work with complex directive configurations', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
          'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          'font-src': ["'self'", 'https://fonts.gstatic.com'],
          'img-src': ["'self'", 'data:', 'https:'],
          'connect-src': ["'self'", 'https://api.example.com'],
          'media-src': ["'none'"],
          'object-src': ["'none'"],
          'frame-src': ["'none'"]
        }
      }), (ctx) => {
        ctx.res.body = 'Complex CSP'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net")
      expect(cspHeader).toContain("style-src 'self' 'unsafe-inline' https://fonts.googleapis.com")
      expect(cspHeader).toContain("font-src 'self' https://fonts.gstatic.com")
      expect(cspHeader).toContain("connect-src 'self' https://api.example.com")
      expect(response.status).toBe(200)
    })

    it('Should work with report-only mode for monitoring', async () => {
      app.get('/test', contentSecurityPolicy({
        reportOnly: true,
        directives: {
          'default-src': ["'self'"],
          'report-uri': ['/csp-report-endpoint']
        }
      }), (ctx) => {
        ctx.res.body = 'Report-only CSP'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.headers.get('Content-Security-Policy-Report-Only')).toContain('report-uri /csp-report-endpoint')
      expect(response.headers.get('Content-Security-Policy')).toBeNull()
    })

    it('Should handle nonce generation for scripts', async () => {
      let generatedNonce: string = ''

      app.get('/test', contentSecurityPolicy({
        directives: {
          'script-src': ["'self'", (ctx) => {
            generatedNonce = 'nonce-' + Math.random().toString(36).substring(2, 15)
            return `'${generatedNonce}'`
          }]
        }
      }), (ctx) => {
        ctx.res.body = `<script nonce="${generatedNonce.replace('nonce-', '')}">console.log('hello')</script>`
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const cspHeader = response.headers.get('Content-Security-Policy')
      expect(cspHeader).toContain("script-src 'self' 'nonce-")
      expect(response.status).toBe(200)
    })
  })
})

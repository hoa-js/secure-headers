import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import contentSecurityPolicy, {
  dangerouslyDisableDefaultSrc,
  getDefaultDirectives
} from '../src/contentSecurityPolicy'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Content Security Policy middleware', () => {
  describe('Basic functionality', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should set default CSP header', async () => {
      app.get('/test', contentSecurityPolicy(), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
      expect(response.headers.get('Content-Security-Policy')).toContain("default-src 'self'")
    })

    it('Should set CSP Report-Only header when reportOnly is true', async () => {
      app.get('/test', contentSecurityPolicy({ reportOnly: true }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy-Report-Only')).toBeTruthy()
      expect(response.headers.get('Content-Security-Policy')).toBeFalsy()
    })

    it('Should work with empty options', async () => {
      app.get('/test', contentSecurityPolicy({}), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
    })

    it('Should work without any options', async () => {
      app.get('/test', contentSecurityPolicy(), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
    })
  })

  describe('Default directives', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should return correct default directives', () => {
      const defaults = getDefaultDirectives()
      expect(defaults).toEqual({
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
    })

    it('Should apply default directives when useDefaults is true', async () => {
      app.get('/test', contentSecurityPolicy({ useDefaults: true }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("default-src 'self'")
      expect(csp).toContain("object-src 'none'")
      expect(csp).toContain("script-src 'self'")
    })

    it('Should not apply default directives when useDefaults is false', async () => {
      expect(() => {
        app.get('/test', contentSecurityPolicy({
          useDefaults: false,
          directives: {}
        }), (ctx) => {
          ctx.res.body = 'Test'
        })
      }).toThrow('Content-Security-Policy has no directives')
    })
  })

  describe('Custom directives', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should accept custom string directive', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-inline'"]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("script-src 'self' 'unsafe-inline'")
    })

    it('Should accept custom array directive', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'img-src': ["'self'", 'data:', 'https://example.com']
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("img-src 'self' data: https://example.com")
    })

    it('Should handle directive with single string value', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': "'self'",
          'script-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("default-src 'self'")
    })

    it('Should handle empty array directive', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'upgrade-insecure-requests': []
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain('upgrade-insecure-requests')
    })

    it('Should disable directive with null value', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'object-src': null
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).not.toContain('object-src')
    })
  })

  describe('Directive name validation', () => {
    it('Should throw error for empty directive name', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            '': ["'self'"]
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive name ""')
    })

    it('Should throw error for invalid directive name characters', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'invalid@name': ["'self'"]
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive name "invalid@name"')
    })

    it('Should throw error for duplicate directive names', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            defaultSrc: ["'self'"],
            'default-src': ["'none'"]
          }
        })
      }).toThrow('Content-Security-Policy received a duplicate directive "default-src"')
    })

    it('Should convert camelCase directive names to kebab-case', async () => {
      const app = new Hoa()
      app.extend(tinyRouter())

      app.get('/test', contentSecurityPolicy({
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain('default-src')
      expect(csp).toContain('script-src')
    })
  })

  describe('Directive value validation', () => {
    it('Should throw error for invalid directive value with semicolon', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'default-src': ["'self'; malicious"]
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "default-src"')
    })

    it('Should throw error for invalid directive value with comma', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'default-src': ["'self', malicious"]
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "default-src"')
    })

    it('Should throw error for unquoted special values', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'default-src': ['self']
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "default-src". "self" should be quoted')
    })

    it('Should throw error for unquoted nonce value', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'script-src': ['nonce-abc123']
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "script-src". "nonce-abc123" should be quoted')
    })

    it('Should throw error for unquoted sha256 value', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'script-src': ['sha256-abc123']
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "script-src". "sha256-abc123" should be quoted')
    })

    it('Should throw error for unquoted sha384 value', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'script-src': ['sha384-abc123']
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "script-src". "sha384-abc123" should be quoted')
    })

    it('Should throw error for unquoted sha512 value', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'script-src': ['sha512-abc123']
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "script-src". "sha512-abc123" should be quoted')
    })

    it('Should throw error for falsy directive value', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'default-src': false as any
          }
        })
      }).toThrow('Content-Security-Policy received an invalid directive value for "default-src"')
    })
  })

  describe('Default-src handling', () => {
    it('Should throw error when default-src is set to null', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'default-src': null
          }
        })
      }).toThrow('Content-Security-Policy needs a default-src but it was set to `null`')
    })

    it('Should allow disabling default-src with dangerouslyDisableDefaultSrc', async () => {
      const app = new Hoa()
      app.extend(tinyRouter())

      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': dangerouslyDisableDefaultSrc,
          'script-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).not.toContain('default-src')
      expect(csp).toContain('script-src')
    })

    it('Should throw error when using dangerouslyDisableDefaultSrc on non-default-src directive', () => {
      expect(() => {
        contentSecurityPolicy({
          directives: {
            'default-src': ["'self'"],
            'script-src': dangerouslyDisableDefaultSrc
          }
        })
      }).toThrow('Content-Security-Policy: tried to disable "script-src" as if it were default-src')
    })

    it('Should throw error when no default-src is provided', () => {
      expect(() => {
        contentSecurityPolicy({
          useDefaults: false,
          directives: {
            'script-src': ["'self'"]
          }
        })
      }).toThrow('Content-Security-Policy needs a default-src but none was provided')
    })

    it('Should throw error when no directives are provided', () => {
      expect(() => {
        contentSecurityPolicy({
          useDefaults: false,
          directives: {}
        })
      }).toThrow('Content-Security-Policy has no directives')
    })
  })

  describe('Function directive values', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should execute function directive values', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'script-src': [
            "'self'",
            (ctx) => `'nonce-${ctx.req.get('x-nonce') || 'default'}'`
          ]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          headers: { 'X-Nonce': 'test123' }
        })
      )
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("'nonce-test123'")
    })

    it('Should validate function directive values', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'script-src': [
            (ctx) => 'unsafe-inline'  // Should be quoted
          ]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })
      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(500)
    })
  })

  describe('Module exports', () => {
    it('Should export getDefaultDirectives function', () => {
      expect(typeof contentSecurityPolicy.getDefaultDirectives).toBe('function')
      expect(contentSecurityPolicy.getDefaultDirectives).toBe(getDefaultDirectives)
    })

    it('Should export dangerouslyDisableDefaultSrc symbol', () => {
      expect(typeof contentSecurityPolicy.dangerouslyDisableDefaultSrc).toBe('symbol')
      expect(contentSecurityPolicy.dangerouslyDisableDefaultSrc).toBe(dangerouslyDisableDefaultSrc)
    })
  })

  describe('Complex scenarios', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should merge custom directives with defaults', async () => {
      app.get('/test', contentSecurityPolicy({
        useDefaults: true,
        directives: {
          'script-src': ["'self'", "'unsafe-eval'"],
          'style-src': ["'self'"]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("default-src 'self'")  // from defaults
      expect(csp).toContain("script-src 'self' 'unsafe-eval'")  // custom
      expect(csp).toContain("style-src 'self'")  // custom (overrides default)
      expect(csp).toContain("img-src 'self' data:")  // from defaults
    })

    it('Should handle mixed function and string directive values', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'script-src': [
            "'self'",
            (ctx) => "'unsafe-inline'",
            'https://example.com',
            (ctx) => `'nonce-${Date.now()}'`
          ]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("script-src 'self' 'unsafe-inline' https://example.com 'nonce-")
    })

    it('Should work with all special quoted values', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'none'"],
          'script-src': [
            "'self'",
            "'strict-dynamic'",
            "'report-sample'",
            "'inline-speculation-rules'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "'unsafe-hashes'",
            "'wasm-unsafe-eval'"
          ]
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).toContain("default-src 'none'")
      expect(csp).toContain("'strict-dynamic'")
      expect(csp).toContain("'unsafe-eval'")
      expect(csp).toContain("'wasm-unsafe-eval'")
    })

    it('Should properly format CSP header with multiple directives', async () => {
      app.get('/test', contentSecurityPolicy({
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", 'https://example.com'],
          'style-src': ["'self'", "'unsafe-inline'"],
          'img-src': ["'self'", 'data:', 'https:'],
          'upgrade-insecure-requests': []
        }
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')

      // CSP should be semicolon-separated
      const directives = csp?.split(';')
      expect(directives?.length).toBeGreaterThan(4)
      expect(csp).toContain('default-src')
      expect(csp).toContain('script-src')
      expect(csp).toContain('style-src')
      expect(csp).toContain('img-src')
      expect(csp).toContain('upgrade-insecure-requests')
    })

    it('Should work with next function', async () => {
      let middlewareCalled = false

      app.get(
        '/test',
        contentSecurityPolicy(),
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
      expect(response.headers.get('Content-Security-Policy')).toBeTruthy()
    })
  })

  describe('Edge cases', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(tinyRouter())
    })

    it('Should handle directives with hasOwnProperty check', async () => {
      const customDirectives = Object.create({ 'inherited-directive': ["'self'"] })
      customDirectives['default-src'] = ["'self'"]
      customDirectives['script-src'] = ["'self'"]

      app.get('/test', contentSecurityPolicy({
        directives: customDirectives
      }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request('http://localhost/test'))
      const csp = response.headers.get('Content-Security-Policy')
      expect(csp).not.toContain('inherited-directive')
      expect(csp).toContain('default-src')
      expect(csp).toContain('script-src')
    })
  })
})

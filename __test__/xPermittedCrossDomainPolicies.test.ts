import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  xPermittedCrossDomainPolicies,
} from '../src/xPermittedCrossDomainPolicies'
import { tinyRouter } from '@hoajs/tiny-router'

describe('X-Permitted-Cross-Domain-Policies middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })

  it('Should set default X-Permitted-Cross-Domain-Policies header', async () => {
    app.get('/test', xPermittedCrossDomainPolicies(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBeTruthy()
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none')
  })

  it('Should set X-Permitted-Cross-Domain-Policies header when options is empty', async () => {
    app.get('/test', xPermittedCrossDomainPolicies({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBeTruthy()
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none')
  })

  it('Should set X-Permitted-Cross-Domain-Policies to none when permittedPolicies is none', async () => {
    app.get('/test', xPermittedCrossDomainPolicies({ permittedPolicies: 'none' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none')
  })

  it('Should set X-Permitted-Cross-Domain-Policies to master-only when permittedPolicies is master-only', async () => {
    app.get('/test', xPermittedCrossDomainPolicies({ permittedPolicies: 'master-only' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('master-only')
  })

  it('Should set X-Permitted-Cross-Domain-Policies to by-content-type when permittedPolicies is by-content-type', async () => {
    app.get('/test', xPermittedCrossDomainPolicies({ permittedPolicies: 'by-content-type' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('by-content-type')
  })

  it('Should set X-Permitted-Cross-Domain-Policies to all when permittedPolicies is all', async () => {
    app.get('/test', xPermittedCrossDomainPolicies({ permittedPolicies: 'all' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('all')
  })

  it('Should handle all valid permittedPolicies values correctly', async () => {
    const policies = ['none', 'master-only', 'by-content-type', 'all'] as const

    for (const policy of policies) {
      app.get(`/test-${policy}`, xPermittedCrossDomainPolicies({ permittedPolicies: policy }), (ctx) => {
        ctx.res.body = 'Test'
      })

      const response = await app.fetch(new Request(`http://localhost/test-${policy}`))
      expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe(policy)
    }
  })

  it.each([
    'invalid',
    'allow-all',
    'deny',
    '',
    'NONE',
    'ALL',
  ])('Should throw error when permittedPolicies is invalid: %s', (permittedPolicies) => {
    expect(() => {
      xPermittedCrossDomainPolicies({ permittedPolicies: permittedPolicies as any })
    }).toThrow(/X-Permitted-Cross-Domain-Policies does not support/)
  })

  it('Should throw error with proper message format for invalid permittedPolicies', () => {
    const invalidPolicy = 'invalid-policy'
    expect(() => {
      xPermittedCrossDomainPolicies({ permittedPolicies: invalidPolicy as any })
    }).toThrow(`X-Permitted-Cross-Domain-Policies does not support ${JSON.stringify(invalidPolicy)}`)
  })

  it('Should handle numeric permittedPolicies values by throwing error', () => {
    expect(() => {
      xPermittedCrossDomainPolicies({ permittedPolicies: 123 as any })
    }).toThrow(/X-Permitted-Cross-Domain-Policies does not support/)
  })

  it('Should handle null permittedPolicies values by throwing error', () => {
    expect(() => {
      xPermittedCrossDomainPolicies({ permittedPolicies: null as any })
    }).toThrow(/X-Permitted-Cross-Domain-Policies does not support/)
  })

  it('Should handle undefined permittedPolicies values by using default', async () => {
    app.get('/test', xPermittedCrossDomainPolicies({ permittedPolicies: undefined }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none')
  })

  it('Should handle boolean permittedPolicies values by throwing error', () => {
    expect(() => {
      xPermittedCrossDomainPolicies({ permittedPolicies: true as any })
    }).toThrow(/X-Permitted-Cross-Domain-Policies does not support/)
  })

  it('Should handle object permittedPolicies values by throwing error', () => {
    expect(() => {
      xPermittedCrossDomainPolicies({ permittedPolicies: {} as any })
    }).toThrow(/X-Permitted-Cross-Domain-Policies does not support/)
  })

  it('Should handle array permittedPolicies values by throwing error', () => {
    expect(() => {
      xPermittedCrossDomainPolicies({ permittedPolicies: ['none'] as any })
    }).toThrow(/X-Permitted-Cross-Domain-Policies does not support/)
  })
})

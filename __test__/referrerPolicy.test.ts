import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  referrerPolicy,
} from '../src/referrerPolicy'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Referrer-Policy middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })

  it('Should set default Referrer-Policy header', async () => {
    app.get('/test', referrerPolicy(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBeTruthy()
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer')
  })

  it('Should set Referrer-Policy header when options is empty', async () => {
    app.get('/test', referrerPolicy({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBeTruthy()
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer')
  })

  it('Should set default Referrer-Policy header when options.policy is undefined', async () => {
    app.get('/test', referrerPolicy({ policy: undefined }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBeTruthy()
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer')
  })

  it.each([
    'no-referrer',
    'no-referrer-when-downgrade',
    'same-origin',
    'origin',
    'strict-origin',
    'origin-when-cross-origin',
    'strict-origin-when-cross-origin',
    'unsafe-url',
    ''
  ] as const)('sets "Referrer-Policy: %s" when told to', async (policy) => {
    app.get('/test', referrerPolicy({ policy }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBe(policy)
  })

  it('Should set multiple policies with array', async () => {
    const policies = ['no-referrer', 'strict-origin-when-cross-origin']
    app.get('/test', referrerPolicy({ policy: policies as any }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBeTruthy()
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer,strict-origin-when-cross-origin')
  })

  it('Should set single policy in array format', async () => {
    app.get('/test', referrerPolicy({ policy: ['same-origin'] }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBeTruthy()
    expect(response.headers.get('Referrer-Policy')).toBe('same-origin')
  })

  it('Should throw error when policy array is empty', () => {
    expect(() => {
      referrerPolicy({ policy: [] })
    }).toThrow('Referrer-Policy received no policy tokens')
  })

  it.each([
    'foo',
    'NO-REFERRER',
    'invalid-policy',
    123,
    null,
    Object('no-referrer'),
  ])('Should throw error when policy is not allowed', (policy) => {
    expect(() => {
      referrerPolicy({ policy: policy as any })
    }).toThrow()
  })

  it('Should throw error when array contains invalid policy', () => {
    expect(() => {
      referrerPolicy({ policy: ['no-referrer', 'invalid-policy'] as any })
    }).toThrow('Referrer-Policy received an unexpected policy token "invalid-policy"')
  })

  it('Should throw error when array contains duplicate policies', () => {
    expect(() => {
      referrerPolicy({ policy: ['no-referrer', 'same-origin', 'no-referrer'] })
    }).toThrow('Referrer-Policy received a duplicate policy token "no-referrer"')
  })

  it('Should work with complex policy combinations', async () => {
    const policies = ['origin', 'strict-origin-when-cross-origin', 'unsafe-url']
    app.get('/test', referrerPolicy({ policy: policies as any }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBe('origin,strict-origin-when-cross-origin,unsafe-url')
  })

  it('Should handle empty string policy', async () => {
    app.get('/test', referrerPolicy({ policy: '' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBe('')
  })

  it('Should handle array with empty string policy', async () => {
    app.get('/test', referrerPolicy({ policy: [''] }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Referrer-Policy')).toBe('')
  })
})

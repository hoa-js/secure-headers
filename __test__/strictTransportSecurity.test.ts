import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  strictTransportSecurity,
} from '../src/strictTransportSecurity'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Strict-Transport-Security middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })

  it('Should set default Strict-Transport-Security header', async () => {
    app.get('/test', strictTransportSecurity(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains')
  })

  it('Should set Strict-Transport-Security header when options is empty', async () => {
    app.get('/test', strictTransportSecurity({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBeTruthy()
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains')
  })

  it('Should set custom maxAge value', async () => {
    app.get('/test', strictTransportSecurity({ maxAge: 86400 }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=86400; includeSubDomains')
  })

  it('Should handle maxAge of 0', async () => {
    app.get('/test', strictTransportSecurity({ maxAge: 0 }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=0; includeSubDomains')
  })

  it('Should handle maxAge as decimal number (should be floored)', async () => {
    app.get('/test', strictTransportSecurity({ maxAge: 86400.9 }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=86400; includeSubDomains')
  })

  it('Should exclude includeSubDomains when set to false', async () => {
    app.get('/test', strictTransportSecurity({ includeSubDomains: false }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=31536000')
  })

  it('Should include includeSubDomains when set to true', async () => {
    app.get('/test', strictTransportSecurity({ includeSubDomains: true }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains')
  })

  it('Should include preload when set to true', async () => {
    app.get('/test', strictTransportSecurity({ preload: true }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains; preload')
  })

  it('Should not include preload when set to false', async () => {
    app.get('/test', strictTransportSecurity({ preload: false }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains')
  })

  it('Should handle all options together', async () => {
    app.get('/test', strictTransportSecurity({
      maxAge: 86400,
      includeSubDomains: false,
      preload: true
    }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=86400; preload')
  })

  it('Should handle all options enabled', async () => {
    app.get('/test', strictTransportSecurity({
      maxAge: 86400,
      includeSubDomains: true,
      preload: true
    }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Strict-Transport-Security')).toBe('max-age=86400; includeSubDomains; preload')
  })

  it.each([
    -1,
    -100,
    NaN,
    Infinity,
    -Infinity,
  ])('Should throw error when maxAge is invalid: %s', (maxAge) => {
    expect(() => {
      strictTransportSecurity({ maxAge })
    }).toThrow(/is not a valid value for maxAge/)
  })

  it('Should throw error when using deprecated maxage property', () => {
    expect(() => {
      strictTransportSecurity({ maxage: 86400 } as any)
    }).toThrow('Strict-Transport-Security received an unsupported property, `maxage`. Did you mean to pass `maxAge`?')
  })

  it('Should throw error when using deprecated includeSubdomains property', () => {
    expect(() => {
      strictTransportSecurity({ includeSubdomains: true } as any)
    }).toThrow('Strict-Transport-Security middleware should use `includeSubDomains` instead of `includeSubdomains`. (The correct one has an uppercase "D".)')
  })
})

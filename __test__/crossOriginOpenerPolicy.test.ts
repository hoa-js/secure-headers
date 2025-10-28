import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  crossOriginOpenerPolicy,
} from '../src/crossOriginOpenerPolicy'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Cross-Origin-Opener-Policy middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })

  it('Should set default Cross-Origin-Opener-Policy header', async () => {
    app.get('/test', crossOriginOpenerPolicy(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toContain('same-origin')
  })

  it('Should set Cross-Origin-Opener-Policy header when options is empty', async () => {
    app.get('/test', crossOriginOpenerPolicy({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toContain('same-origin')
  })

  it('Should set default Cross-Origin-Opener-Policy header when options.policy is undefined', async () => {
    app.get('/test', crossOriginOpenerPolicy({ policy: undefined }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toContain('same-origin')
  })

  it.each(['same-origin', 'same-origin-allow-popups', 'unsafe-none'] as const)('sets "Cross-Origin-Opener-Policy: %s" when told to', async (policy) => {
    app.get('/test', crossOriginOpenerPolicy({ policy }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Opener-Policy')).toContain(policy)
  })

  it.each([
    '',
    'foo',
    'SAME-ORIGIN',
    123,
    null,
    Object('same-origin'),
  ])('Should throw error when policy is not allowed', (policy) => {
    expect(() => {
      crossOriginOpenerPolicy({ policy: policy as any })
    }).toThrow()
  })
})

import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  crossOriginResourcePolicy,
} from '../src/crossOriginResourcePolicy'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Cross-Origin-Resource-Policy middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })

  it('Should set default Cross-Origin-Resource-Policy header', async () => {
    app.get('/test', crossOriginResourcePolicy(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toContain('same-origin')
  })

  it('Should set Cross-Origin-Resource-Policy header when options is empty', async () => {
    app.get('/test', crossOriginResourcePolicy({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toContain('same-origin')
  })

  it('Should set default Cross-Origin-Resource-Policy header when options.policy is undefined', async () => {
    app.get('/test', crossOriginResourcePolicy({ policy: undefined }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toContain('same-origin')
  })

  it.each(['same-origin', 'same-site', 'cross-origin'] as const)('sets "Cross-Origin-Resource-Policy: %s" when told to', async (policy) => {
    app.get('/test', crossOriginResourcePolicy({ policy }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Resource-Policy')).toContain(policy)
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
      crossOriginResourcePolicy({ policy: policy as any })
    }).toThrow()
  })
})

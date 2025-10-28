import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  crossOriginEmbedderPolicy,
} from '../src/crossOriginEmbedderPolicy'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Cross-Origin-Embedder-Policy middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })

  it('Should set default Cross-Origin-Embedder-Policy header', async () => {
    app.get('/test', crossOriginEmbedderPolicy(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toContain('require-corp')
  })

  it('Should set default Cross-Origin-Embedder-Policy header when options is empty', async () => {
    app.get('/test', crossOriginEmbedderPolicy({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toContain('require-corp')
  })

  it('Should set default Cross-Origin-Embedder-Policy header when options.policy is undefined', async () => {
    app.get('/test', crossOriginEmbedderPolicy({ policy: undefined }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toContain('require-corp')
  })

  it.each(['require-corp', 'credentialless', 'unsafe-none'] as const)('sets "Cross-Origin-Embedder-Policy: %s" when told to', async (policy) => {
    app.get('/test', crossOriginEmbedderPolicy({ policy }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toBeTruthy()
    expect(response.headers.get('Cross-Origin-Embedder-Policy')).toContain(policy)
  })

  it.each([
    '',
    'foo',
    'CREDENTIALLESS',
    123,
    null,
    Object('credentialless'),
  ])('Should throw error when policy is not allowed', (policy) => {
    expect(() => {
      crossOriginEmbedderPolicy({ policy: policy as any })
    }).toThrow()
  })
})

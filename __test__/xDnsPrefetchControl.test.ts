import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  xDnsPrefetchControl,
} from '../src/xDnsPrefetchControl'
import { tinyRouter } from '@hoajs/tiny-router'

describe('X-DNS-Prefetch-Control middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })
  it('Should set header to "off" when no options', async () => {
    app.get('/test', xDnsPrefetchControl(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-DNS-Prefetch-Control')).toBeTruthy()
    expect(response.headers.get('X-DNS-Prefetch-Control')).toContain('off')
  })

  it('Should set header to "off" when options is empty', async () => {
    app.get('/test', xDnsPrefetchControl({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-DNS-Prefetch-Control')).toBeTruthy()
    expect(response.headers.get('X-DNS-Prefetch-Control')).toContain('off')
  })

  it('Should set header to "off" when options.allow is false', async () => {
    app.get('/test', xDnsPrefetchControl({ allow: false }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-DNS-Prefetch-Control')).toBeTruthy()
    expect(response.headers.get('X-DNS-Prefetch-Control')).toContain('off')
  })

  it('Should set header to "on" when options.allow is true', async () => {
    app.get('/test', xDnsPrefetchControl({ allow: true }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-DNS-Prefetch-Control')).toBeTruthy()
    expect(response.headers.get('X-DNS-Prefetch-Control')).toContain('on')
  })
})

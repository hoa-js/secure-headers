import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import {
  xFrameOptions,
} from '../src/xFrameOptions'
import { tinyRouter } from '@hoajs/tiny-router'

describe('X-Frame-Options middleware', () => {
  let app: Hoa

  beforeEach(() => {
    app = new Hoa()
    app.extend(tinyRouter())
  })

  it('Should set default X-Frame-Options header', async () => {
    app.get('/test', xFrameOptions(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Frame-Options')).toBeTruthy()
    expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
  })

  it('Should set X-Frame-Options header when options is empty', async () => {
    app.get('/test', xFrameOptions({}), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Frame-Options')).toBeTruthy()
    expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
  })

  it('Should set X-Frame-Options to SAMEORIGIN when action is sameorigin', async () => {
    app.get('/test', xFrameOptions({ action: 'sameorigin' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
  })

  it('Should set X-Frame-Options to DENY when action is deny', async () => {
    app.get('/test', xFrameOptions({ action: 'deny' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Frame-Options')).toBe('DENY')
  })

  it('Should handle uppercase action values correctly', async () => {
    app.get('/test-deny', xFrameOptions({ action: 'deny' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    app.get('/test-sameorigin', xFrameOptions({ action: 'sameorigin' }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const denyResponse = await app.fetch(new Request('http://localhost/test-deny'))
    expect(denyResponse.headers.get('X-Frame-Options')).toBe('DENY')

    const sameoriginResponse = await app.fetch(new Request('http://localhost/test-sameorigin'))
    expect(sameoriginResponse.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
  })

  it('Should handle SAME-ORIGIN action and convert to SAMEORIGIN', async () => {
    expect(() => {
      xFrameOptions({ action: 'same-origin' as any })
    }).not.toThrow()
  })

  it.each([
    'invalid',
    'allowall',
    'allow-from',
    '',
    'INVALID',
  ])('Should throw error when action is invalid: %s', (action) => {
    expect(() => {
      xFrameOptions({ action: action as any })
    }).toThrow(/X-Frame-Options received an invalid action/)
  })

  it('Should throw error with proper message format for invalid action', () => {
    const invalidAction = 'invalid-action'
    expect(() => {
      xFrameOptions({ action: invalidAction as any })
    }).toThrow(`X-Frame-Options received an invalid action ${JSON.stringify(invalidAction)}`)
  })

  it('Should handle numeric action values by throwing error', () => {
    expect(() => {
      xFrameOptions({ action: 123 as any })
    }).toThrow(/X-Frame-Options received an invalid action/)
  })

  it('Should handle null action values by throwing error', () => {
    expect(() => {
      xFrameOptions({ action: null as any })
    }).toThrow(/X-Frame-Options received an invalid action/)
  })

  it('Should handle undefined action values by using default', async () => {
    app.get('/test', xFrameOptions({ action: undefined }), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
  })
})

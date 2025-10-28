import { Hoa } from 'hoa'
import { describe, it, expect } from '@jest/globals'
import {
  xXssProtection,
} from '../src/xXssProtection'
import { tinyRouter } from '@hoajs/tiny-router'

describe('X-XSS-Protection middleware', () => {
  it('Should set X-XSS-Protection header', async () => {
    const app = new Hoa()
    app.extend(tinyRouter())
    app.get('/test', xXssProtection(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-XSS-Protection')).toBeTruthy()
    expect(response.headers.get('X-XSS-Protection')).toContain('0')
  })
})

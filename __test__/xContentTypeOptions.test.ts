import { Hoa } from 'hoa'
import { describe, it, expect } from '@jest/globals'
import {
  xContentTypeOptions,
} from '../src/xContentTypeOptions'
import { tinyRouter } from '@hoajs/tiny-router'

describe('X-Content-Type-Options middleware', () => {
  it('Should set', async () => {
    const app = new Hoa()
    app.extend(tinyRouter())
    app.get('/test', xContentTypeOptions(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Content-Type-Options')).toBeTruthy()
    expect(response.headers.get('X-Content-Type-Options')).toContain('nosniff')
  })
})

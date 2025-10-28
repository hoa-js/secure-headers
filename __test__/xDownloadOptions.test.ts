import { Hoa } from 'hoa'
import { describe, it, expect } from '@jest/globals'
import {
  xDownloadOptions,
} from '../src/xDownloadOptions'
import { tinyRouter } from '@hoajs/tiny-router'

describe('X-Download-Options middleware', () => {
  it('Should set X-Download-Options', async () => {
    const app = new Hoa()
    app.extend(tinyRouter())
    app.get('/test', xDownloadOptions(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('X-Download-Options')).toBeTruthy()
    expect(response.headers.get('X-Download-Options')).toContain('noopen')
  })
})

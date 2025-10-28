import { Hoa } from 'hoa'
import { describe, it, expect } from '@jest/globals'
import {
  originAgentCluster,
} from '../src/originAgentCluster'
import { tinyRouter } from '@hoajs/tiny-router'

describe('Origin Agent Cluster middleware', () => {
  it('Should set Origin Agent Cluster header', async () => {
    const app = new Hoa()
    app.extend(tinyRouter())
    app.get('/test', originAgentCluster(), (ctx) => {
      ctx.res.body = 'Test'
    })

    const response = await app.fetch(new Request('http://localhost/test'))
    expect(response.status).toBe(200)
    expect(response.headers.get('Origin-Agent-Cluster')).toBeTruthy()
    expect(response.headers.get('Origin-Agent-Cluster')).toContain('?1')
  })
})

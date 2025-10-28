import type { HoaContext, HoaMiddleware } from 'hoa'

export function originAgentCluster (): HoaMiddleware {
  return async function originAgentClusterMiddleware (
    ctx: HoaContext,
    next: () => Promise<void>
  ) {
    ctx.res.set('Origin-Agent-Cluster', '?1')
    await next()
  }
}

export default originAgentCluster

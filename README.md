## @hoajs/secure-headers

SecureHeaders middleware for Hoa.

## Installation

```bash
$ npm i @hoajs/secure-headers --save
```

## Quick Start

```js
import { Hoa } from 'hoa'
import {secureHeaders } from '@hoajs/secure-headers'

const app = new Hoa()
app.use(secureHeaders())

app.use(async (ctx) => {
  ctx.res.body = `Hello, Hoa!`
})

export default app
```

## Documentation

The documentation is available on [hoa-js.com](https://hoa-js.com/middleware/secure-headers.html)

## Test (100% coverage)

```sh
$ npm test
```

## License

MIT


| module | header |  hono | helmet | hoajs |
| --- | --- | :---: | :---: | :---: |
| Content-Security-Policy | 用法 | ✅ | ✅ | ✅ |
| Cross-origin-Embedder-Policy | 用法| ✅ | ✅ | ✅ |
| Cross-Origin-Opener-Policy | 用法| ✅ | ✅ | ✅ |
| Cross-Origin-Resource-Policy | 用法| ✅ | ✅ | ✅ |
| Origin-Agent-Cluster | 用法| ✅ | ✅ | ✅ |
| Referrer-Policy | 用法| ✅ | ✅ | ✅ |
| Strict-Transport-Security | 用法| ✅ | ✅ | ✅ |
| X-Content-Type-Options | 用法| ✅ | ✅ | ✅ |
| X-DNS-Prefetch-Control | 用法| ✅ | ✅ | ✅ |
| X-Download-Options | 用法| ✅ | ✅ | ✅ |
| X-Frame-Options | 用法| ✅ | ✅ | ✅ |
| X-Permitted-Cross-Domain-Policies | 用法| ✅ | ✅ | ✅ |
| X-XSS-Protection | 用法| ✅ | ✅ | ✅ |
| Permissions-Policy | 用法| ✅ | ❌ | ✅ |

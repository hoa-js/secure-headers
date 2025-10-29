## @hoajs/secure-headers

SecureHeaders middleware for Hoa.

## Installation

```bash
$ npm i @hoajs/secure-headers --save
```

## Quick Start

```js
import { Hoa } from 'hoa'
import { secureHeaders } from '@hoajs/secure-headers'

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

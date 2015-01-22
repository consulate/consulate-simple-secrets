consulate-simple-secrets [![Build Status](https://travis-ci.org/consulate/consulate-simple-secrets.png?branch=master)](https://travis-ci.org/consulate/consulate-simple-secrets)
========================

[simple-secrets](https://github.com/timshadel/simple-secrets) token plugin for [consulate](https://github.com/consulate/consulate)

Usage
-----

Just register `consulate-simple-secrets` as a plugin with your [consulate](https://github.com/consulate/consulate) server:

```js
var consulate = require('consulate')
  , ss = require('consulate-simple-secrets');

var app = consulate();

app.plugin(ss({
  key: '3b6006d164bae955136a5befea9d0e4a50c22a2f7be5d65c2fd67752625deee3'
}));
```

This will return encrypted tokens with embedded token information:

```js
{
  u: 'user-id',
  s: 42, // compressed scopes
  c: 'client-id',
  e: 1234 // expiration date
}
```

`TODO` explain how to extract token information

Advanced Usage
--------------

The options accepts a `transform` function to change the token information. This can be used to add extra fields in the token.

```js
app.plugin(ss({
  transform: function(client, user, scope, availableScopes, tokenOpts, done) {
    // transform the tokenOpts here

    done(null, tokenOpts);
  }
}));
```

Tests
-----

```sh
$ npm test
```

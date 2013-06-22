/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate-simple-secrets')
  , ss = require("simple-secrets")
  , SmD = require('smd');

/**
 * Simple Secrets issue token for consulate
 *
 * @param {Object} options
 * @return {Function}
 */

module.exports = function(options) {
  // Check that they gave us a key to sign
  if (!options || !options.key) throw new Error("Missing a `key` for simple-secrets signer");

  // Create a sender
  var key = new Buffer(options.key, 'hex')
    , sender = ss(key);

  var ttl = options.ttl || 1;

  debug('using ttl of', ttl);

  function register(app) {

    // Save the `scopes` callback for compression
    var getScopes = app.callback('scopes');

    // Allow the consumer to map scopes to a compressed enum value
    var compress = options.compressScope || compressScope;

    app.issueToken(function(client, user, scope, done) {
      debug('issuing token for client', client, 'and user', user, 'with scope', scope);

      // Get a list of the scopes enum
      getScopes(function(err, scopesEnum) {
        if (err) return done(err);

        var expires = SmD.from(Date.now() + (ttl+0.7)*SmD.ms_per_unit);

        // Create a token with simple-secrets
        // We use short variable names since we want to keep the size of our token down
        var token = sender.pack({
          u: user ? user.id : null,
          s: compress(scope, scopesEnum),
          c: client.id,
          e: expires
        });

        debug('issued token', token);

        done(null, token, null, { expires_in: SmD.seconds_from_now(expires) });
      });
    });
  };

  // Expose the sender
  register.sender = sender;

  return register;
};

/**
 * Compress scopes with an emum into an efficient integer
 */

function compressScope(scope, scopesEnum) {
  var scopes = typeof scope === 'string'
    ? scope.split(' ')
    : scope;

  var value = '1' + scopesEnum.map(function(scope) {
    return !!~scopes.indexOf(scope) ? '1' : '0';
  }).join('');

  debug('compressing', scopes, 'into', value+'b');

  return parseInt(value, 2);
};

// Expose compressScope for testing

if (process.env.NODE_ENV === 'test') module.exports.compressScope = compressScope;

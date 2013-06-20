/**
 * Module dependencies
 */
var ss = require("simple-secrets");

/**
 * Defines
 */
var MS_PER_HOUR = 60 * 60 * 1000
  , DEFAULT_TTL = Math.pow(2, 16) * MS_PER_HOUR;

module.exports = function(options) {
  // Check that they gave us a key to sign
  if (!options || !options.key) throw new Error("Missing a `key` for simple-secrets signer");

  // Create a sender
  var key = new Buffer(options.key, 'hex')
    , sender = ss(key);

  // Save the ttl
  var ttl = options.ttl || DEFAULT_TTL;

  // Allow the consumer to map scopes to a compressed enum value
  var compressScope = options.compressScope || function(scope) { return scope };

  function register(app) {
    app.issueToken(function(client, user, scope, done) {
      // Create a token with simple-secrets
      // We use short variable names since we want to keep the size of our token down
      var token = sender.pack({
        u: user.id,
        s: compressScope(scope),
        c: client.id,
        e: expire(ttl)
      });

      done(null, token);
    });
  };

  // Expose the sender
  register.sender = sender;

  return register;
};

function expire(ttl) {
  return Math.floor((Date.now() % ttl) / MS_PER_HOUR)
};

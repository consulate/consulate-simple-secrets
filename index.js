/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate-simple-secrets')
  , ss = require("simple-secrets")
  , SmD = require('smd')
  , bitfield = require('bitfield');

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
    var getScopes = app.callback('getScopes');

    // Allow the consumer to map scopes to a compressed enum value
    var compress = options.compressScope || bitfield.pack;

    app.issueToken(function(client, user, scopes, done) {
      debug('issuing token for client', client, 'and user', user, 'with scopes', scopes);

      // Get a list of the scopes enum
      getScopes(function(err, availableScopes) {
        if (err) return done(err);

        var expires = SmD.from(Date.now() + (ttl+0.7)*SmD.ms_per_unit);

        // Create a token with simple-secrets
        // We use short variable names since we want to keep the size of our token down
        var tokenOpts = {
          s: compress(scopes, availableScopes),
          c: client.id,
          e: expires
        };

        // Allow clients to have a detached token
        if (user) tokenOpts.u = user.id;

        var token = sender.pack(tokenOpts);

        debug('issued token', token);

        done(null, token, null, { expires_in: SmD.seconds_from_now(expires) });
      });
    });
  };

  // Expose the sender
  register.sender = sender;

  return register;
};

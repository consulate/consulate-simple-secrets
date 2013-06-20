/**
 * Module dependencies
 */
var ss = require("simple-secrets");

module.exports = function(options) {
  // Check that they gave us a key to sign
  if (!options || !options.key) throw new Error("You must specify a `key` for simple-secrets");

  // Create a sender
  var key = new Buffer(options.key, 'hex')
    , sender = ss(key);

  return function(app) {
    app.issueToken(function(client, user, scope, done) {
      // Create a token with simple-secrets
      // We use short variable names since we want to keep the size of our token down
      var token = sender.pack({
        u: user.id,
        s: scope,
        c: client.id
      });

      done(null, token);
    });
  };
};

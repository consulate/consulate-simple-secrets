/**
 * Module dependencies
 */
var should = require('should')
  , ssPlugin = require('..')
  , ss = require('simple-secrets');

/**
 * Defines
 */
var SECRET = '3b6006d164bae955136a5befea9d0e4a50c22a2f7be5d65c2fd67752625deee3';

describe('consulate-simple-secrets', function() {

  var app;

  var signer = ss(new Buffer(SECRET, 'hex'));

  beforeEach(function() {
    app = {
      'issueToken': function(fn) {
        app.callbacks.issueToken = fn;
      },
      callbacks: {}
    };
  });

  it('should register a `issueToken` callback', function() {
    var options = {key: SECRET}
      , instance = ssPlugin(options);

    instance(app);

    should.exist(app.callbacks.issueToken);
    Object.keys(app.callbacks).should.have.length(1);
  });

  it('should issue a valid token', function(done) {
    var instance = ssPlugin({key: SECRET})(app)

    var client = {id: 'clientId'}
      , user = {id: 'userId'}
      , scope = ['user:email', 'user:name'];

    app.callbacks.issueToken(client, user, scope, function(err, token) {
      var tokenInfo = signer.unpack(token);
      should.exist(tokenInfo);
      should.exist(tokenInfo.e);
      tokenInfo.c.should.eql('clientId');
      tokenInfo.u.should.eql('userId');
      tokenInfo.s.should.eql(['user:email', 'user:name']);

      done();
    });
  });

});

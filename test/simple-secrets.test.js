/**
 * Module dependencies
 */
var should = require('should')
  , ssPlugin = require('..')
  , ss = require('simple-secrets')
  , SmD = require('smd')
  , bitfield = require('bitfield');

/**
 * Defines
 */
var SECRET = '3b6006d164bae955136a5befea9d0e4a50c22a2f7be5d65c2fd67752625deee3';

describe('consulate-simple-secrets', function() {

  var app;

  var signer = ss(new Buffer(SECRET, 'hex'))
    , availableScopes = ['user:email', 'user:name', 'user:address'];

  beforeEach(function() {
    app = {
      'issueToken': function(fn) {
        app.callbacks.issueToken = fn;
      },
      'callback': function() {
        return function(done) {
          done(null, availableScopes);
        }
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

    app.callbacks.issueToken(client, user, scope, function(err, accessToken, params) {
      var tokenInfo = signer.unpack(accessToken);
      should.exist(tokenInfo);
      should.exist(tokenInfo.e);
      should.exist(params);
      // Expect between 10 mins and 2 hours
      params.expires_in.should.be.lessThan(7201);
      params.expires_in.should.be.greaterThan(600);

      // Check actual expiration as well
      var expires_in = (SmD.at(tokenInfo.e) - Date.now()) / 1000;
      expires_in.should.be.lessThan(7201);
      expires_in.should.be.greaterThan(600);

      tokenInfo.c.should.eql('clientId');
      tokenInfo.u.should.eql('userId');

      // Check that it decoded the correct scopes
      var tokenBuf = new Buffer(tokenInfo.s, 'utf8');
      console.log('token', tokenInfo.s, tokenBuf);
      bitfield.unpack(tokenBuf, availableScopes).should.eql(scope);

      done();
    });
  });

  it('should transform the token info', function(done) {

    var instance = ssPlugin({
      key: SECRET,
      transform: function(client, user, scope, availableScopes, tokenOpts, cb) {
        tokenOpts.t = 123;
        cb(null, tokenOpts);
      }
    })(app)

    var client = {id: 'clientId'}
      , user = {id: 'userId'}
      , scope = ['user:email', 'user:name'];

    app.callbacks.issueToken(client, user, scope, function(err, accessToken, params) {
      var tokenInfo = signer.unpack(accessToken);
      should.exist(tokenInfo.t);
      tokenInfo.t.should.eql(123);
      done();
    });
  });

});

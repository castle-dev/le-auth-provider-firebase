var q = require('q');
var Firebase = require('firebase');

var AuthProviderFirebase = function (url) {
  var _ref = new Firebase(url);
  this.createUser = function (email, password) {
    var deferred = q.defer();
    _ref.createUser({
      email: email,
      password: password
    }, function (err, authData) {
      if (err) { deferred.reject(err); }
      else { deferred.resolve(authData.uid); }
    });
    return deferred.promise;
  };
  this.loginWithEmail = function (email, password) {
    var deferred = q.defer();
    _ref.authWithPassword({
      email: email,
      password: password
    }, function (err, authData) {
      if (err) { return deferred.reject(err); }
      else { deferred.resolve(authData.uid); }
    });
    return deferred.promise;
  };
  this.loginWithToken = function (token) {
    var deferred = q.defer();
    _ref.authWithCustomToken(token, function (err) {
      if (err) { return deferred.reject(err); }
      else { deferred.resolve(); }
    });
    return deferred.promise;
  };
  this.isAuthenticated = function () {
    var authData = _ref.getAuth();
    return !!authData;
  };
  this.logout = function () {
    _ref.unauth();
  };
  this.requestPasswordReset = function (email) {
    var deferred = q.defer();
    _ref.resetPassword({ email: email }, function (err) {
      if (err) { deferred.reject(err); }
      else { deferred.resolve(); }
    });
    return deferred.promise;
  };
  this.resetPassword = function (email, token, password) {
    var deferred = q.defer();
    _ref.changePassword({
      email: email,
      oldPassword: token,
      newPassword: password
    }, function(err) {
      if (err) { deferred.reject(err); }
      else { deferred.resolve(); }
    });
    return deferred.promise;
  }
};

module.exports = AuthProviderFirebase;

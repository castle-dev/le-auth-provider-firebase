var q = require('q');
var pluralize = require('pluralize');
/**
 * A bridge between le-auth-service and Firebase
 * @class AuthProvider
 * @param {string} ref the firebase root reference
 * @param {StorageService} storage an instance of le-storage-service that is used to create records
 * @returns {service}
 */
var AuthProvider = function (ref, storage) {
  if (!ref) { throw new Error('Firebase reference required'); }
  var _ref = ref;
  var _storage = storage;
  /**
   * Creates a new user
   * @function createUser
   * @memberof AuthProvider
   * @instance
   * @param {string} email the user's email address
   * @param {string} password the user's password
   * @returns {promise}
   */
  this.createUser = function (email, password, roles) {
    var deferred = q.defer();
    _ref.createUser({
      email: email,
      password: password
    }, function (err, authData) {
      if (err) { deferred.reject(err); }
      else {
        var userData = {
          roles: {}
        };
        roles.forEach(function (role) {
          var roleRef = _ref.child(pluralize(role)).push();
          var roleKey = roleRef.key();
          userData['roles'][role + '_id'] = roleKey;
        });
        var record = _storage.createRecord('User', authData.uid);
        record.update(userData)
        .then(function () {
          deferred.resolve(record);
        });
      }
    });
    return deferred.promise;
  };
  /**
   * Logs a user in, given their email and password
   * @function loginWithEmail
   * @memberof AuthProvider
   * @instance
   * @param {string} email the user's email address
   * @param {string} password the user's password
   * @returns {promise}
   */
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
  /**
   * Logs a user in, given an access token
   * @function loginWithToken
   * @memberof AuthProvider
   * @instance
   * @param {string} token the user's access token
   * @returns {promise}
   */
  this.loginWithToken = function (token) {
    var deferred = q.defer();
    _ref.authWithCustomToken(token, function (err) {
      if (err) { return deferred.reject(err); }
      else { deferred.resolve(); }
    });
    return deferred.promise;
  };
  /**
   * Checks whether a user is currently authenticated
   * @function isAuthenticated
   * @memberof AuthProvider
   * @instance
   * @returns {boolean}
   */
  this.isAuthenticated = function () {
    var authData = _ref.getAuth();
    return !!authData;
  };
  /**
   * Logs a user out
   * @function logout
   * @memberof AuthProvider
   * @instance
   */
  this.logout = function () {
    _ref.unauth();
  };
  /**
   * Send the user a password reset email
   * @function requestPasswordReset
   * @memberof AuthProvider
   * @instance
   * @param {string} email the user's email address
   * @returns {promise}
   */
  this.requestPasswordReset = function (email) {
    var deferred = q.defer();
    _ref.resetPassword({ email: email }, function (err) {
      if (err) { deferred.reject(err); }
      else { deferred.resolve(); }
    });
    return deferred.promise;
  };
  /**
   * Reset a user's password
   * @function resetPassword
   * @memberof AuthProvider
   * @instance
   * @param {string} email the user's email address
   * @param {string} token the password reset token given to the user
   * @param {string} password the user's new password
   * @returns {promise}
   */
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

module.exports = AuthProvider;

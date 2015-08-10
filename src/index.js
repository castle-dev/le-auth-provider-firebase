var q = require('q');
var pluralize = require('pluralize');
/**
 * A bridge between le-auth-service and Firebase
 * @class AuthProvider
 * @param {string} ref the firebase root reference
 * @param {StorageService} storage an instance of le-storage-service that is used to create records
 * @returns {service}
 */
var AuthProvider = function(ref, storage) {
  if (!ref) {
    throw new Error('Firebase reference required');
  }
  if (!storage) {
    throw new Error('Instance of le-storage-service required');
  }
  var _ref = ref;
  var _storage = storage;
  var _provider = this;
  /**
   * Creates a new user
   * @function createUser
   * @memberof AuthProvider
   * @instance
   * @param {string} email the new user's email
   * @param {string} password the new user's password
   * @param {array of strings} roles an array of roles, supported values for the array are 'manager', 'tenant', 'owner', and 'contractor'
   * @param {array of strings} optional, roleIDs the record IDs for the roles, the ids must be passed in the same order as the roles in the roles paramater
   * @param {string} optional, avatarImageID the id for the avatar image for the user
   * @param {string} permissionID optional the id of the permission record for the user record
   * @returns {promise} resolves with the newly created user record
   */
  this.createUser = function(email, password, roles, roleIDs, avatarImageID, permissionID) {
    var deferred = q.defer();
    _ref.createUser({
      email: email,
      password: password
    }, function(err, authData) {
      if (err) {
        deferred.reject(err);
      } else {
        var userData = {
          roles: {}
        };
        for (var i = 0; i < roles.length; i += 1) {
          var roleKey;
          if (roleIDs && roleIDs[i]) {
            roleKey = roleIDs[i];
          } else {
            roleKey = _ref.child(pluralize(roles[i])).push().key();
          }
          userData['roles'][roles[i] + '_id'] = roleKey;
        }
        if (avatarImageID) {
          userData.avatarImage = avatarImageID;
        }
        if (permissionID) {
          userData.permission_id = permissionID;
        }
        var record = _storage.createRecord('User', authData.uid);
        record.update(userData)
          .then(function() {
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
  this.loginWithEmail = function(email, password) {
    var deferred = q.defer();
    _ref.authWithPassword({
      email: email,
      password: password
    }, function(err, authData) {
      if (err) {
        return deferred.reject(err);
      } else {
        deferred.resolve(authData.uid);
      }
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
  this.loginWithToken = function(token) {
    var deferred = q.defer();
    _ref.authWithCustomToken(token, function(err) {
      if (err) {
        return deferred.reject(err);
      } else {
        deferred.resolve();
      }
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
  this.isAuthenticated = function() {
    var authData = _ref.getAuth();
    return !!authData;
  };
  /**
   * Logs a user out
   * @function logout
   * @memberof AuthProvider
   * @instance
   */
  this.logout = function() {
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
  this.requestPasswordReset = function(email) {
    var deferred = q.defer();
    _ref.resetPassword({
      email: email
    }, function(err) {
      if (err) {
        deferred.reject(err);
      } else {
        deferred.resolve();
      }
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
  this.resetPassword = function(email, token, password) {
    var deferred = q.defer();
    _ref.changePassword({
      email: email,
      oldPassword: token,
      newPassword: password
    }, function(err) {
      if (err) {
        deferred.reject(err);
      } else {
        deferred.resolve();
      }
    });
    return deferred.promise;
  };
  /**
   * Returns the authed user's record
   * @function getAuthedUser
   * @memberof AuthProvider
   * @instance
   * @returns {record}
   */
  this.getAuthedUser = function() {
    var authData = _ref.getAuth();
    if (!authData) {
      return;
    }
    return _storage.createRecord('User', authData.uid);
  };
  /**
   * Checks whether the current user has a given role
   * @function authedUserHasRole
   * @memberof AuthProvider
   * @instance
   * @param {string} role the role to check for
   * @returns {promise}
   */
  this.authedUserHasRole = function(role) {
    var deferred = q.defer();
    if (!_provider.isAuthenticated()) {
      deferred.reject();
    } else {
      _provider.getAuthedUser().load()
        .then(function(data) {
          if (typeof data.roles[role + '_id'] === "undefined") {
            deferred.reject();
          } else {
            deferred.resolve()
          }
        }, function(err) {
          deferred.reject(err);
        });
    }
    return deferred.promise;
  };
  /**
   * Returns a map of the authed user's role records
   * @function getAuthedUserRoles
   * @memberof AuthProvider
   * @instance
   * @returns {promise} resolves with a map of user records
   */
  this.getAuthedUserRoles = function() {
    var deferred = q.defer();
    var userRecord = _provider.getAuthedUser();
    if (!userRecord) {
      deferred.reject('User must be authenticated to have roles');
    } else {
      userRecord.load()
        .then(function(data) {
          var recordMap = {};
          for (var key in data.roles) {
            if (data.roles.hasOwnProperty(key)) {
              var role = key.split('_id')[0];
              recordMap[role] = _storage.createRecord(role, data.roles[key]);
            }
          }
          deferred.resolve(recordMap);
        }, function(err) {
          deferred.reject(err);
        });
    }
    return deferred.promise;
  };
};

module.exports = AuthProvider;
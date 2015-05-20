le-auth-provider-firebase
=========

**Connect le-auth-service to Firebase**

## Installation

  `npm install le-auth-provider-firebase`

## Usage

```
  var mandrillAPIKey = /* your api key */
  var EmailProvider = require('le-email-provider-mandrill');
  var provider = new EmailProvider(mandrillAPIKey);
```

## Tests

* `npm test` to run unit tests once
* `gulp tdd` to run unit and e2e tests when tests change
* `gulp coverage` to run unit tests and create a code coverage report

## Contributing

Please follow the project's [conventions](https://github.com/castle-dev/le-auth-provider-firebase/blob/develop/CONTRIBUTING.md) or your changes will not be accepted

## Release History

* 0.1.0 Initial release

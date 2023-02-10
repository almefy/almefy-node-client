# Almefy Node SDK

A simple Node wrapper for the Almefy API.

## Quick Guide

Below is a striped down guide how to integrate Almefy in your Node project to test it easily. We are already
preparing a comprehensive documentation covering all possible use cases and parameters. So stay tuned.

_Please notice: this document is a work in progress and currently addresses node > v8.17.0 for backward compatibility._

### Prerequisites

To successfully initialize the Node SDK, you'll need an API key and API secret from Almefy.

```ini
# Example .env Data (rename .env.sample and fill with your key and secret.)

ALMEFY_GLOBAL_MAIL_LOCALE="de"
ALMEFY_APIHOST="https://api.almefy.com"
ALMEFY_KEY="ALMEFY_KEY_HERE"
ALMEFY_SECRETBASE64="ALMEFY_SECRECT_HERE"
```

### Installation

**Almefy Node SDK** is available on NPM as the [@almefy/sdk](https://www.npmjs.com/package/@almefy/sdk)
package. Run `npm i almefy/sdk` from the root of your project in terminal, and you are done. If you
cannot use `npm` for any reasons you can download the [latest version](https://github.com/almefy/almefy-node-skd/releases)
from GitHub.

### Client Initialization

Once you have the SDK installed in your project, you will need to instantiate a Client object. This example assumes
that you store the secrets in some environment variables:

```js
const api = new AlmefyAPIClient({
                                    apiBaseUrl: process.env.ALMEFY_APIHOST,
                                    apiKey: process.env.ALMEFY_KEY,
                                    apiSecretBase64: process.env.ALMEFY_SECRETBASE64,
                                    debug: false 
                                }, null);
```

### Identity Enrollment

Before a user account can be used with the Almefy app, it needs to be enrolled and the device provisioned. The easiest
way to enroll an account with Almefy is to send the user an email with an enrollment QR Code inside. A good starting point
could be a "Login with Almefy" button somewhere inside the protected area, which triggers the following process in the
backend:

```js
const options = {sendEmail:false}
api.enrollIdentity("john.doe", options).then(result => {
    console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}))
});
```

The returned `enrollmentToken` object provides a public `base64ImageData` member with the base64 encoded image data
that can be used in any HTML email.

If enabled, you can also use the Almefy API to send a generic enrollment email without the effort to build a custom
email-client compatible template:

```js
const options = {sendEmail: true, sendEmailTo: "john.doe@example.com"}
api.enrollIdentity("john.doe", options).then(result => {
    console.log(util.inspect(result, {showHidden: false, depth: null, colors: true}))
});
```
_Notice: Check out the [API Enrollment Reference](https://docs.almefy.com/api/reference.html#enroll-identity) for all available options._

This process creates or uses an existing identity and sends out an enrollment email with a QR Code inside, that needs to
be scanned with the Almefy app to provision it. Once done, the enrollment is completed, and the user is ready to
authenticate using the Almefy app.

### Frontend

Add the following few lines to your HTML frontend to show the Almefy image used for authentication.

```html
<!-- Place this HTML code wherever the Almefy image should appear -->
<div data-almefy-auth
     data-almefy-key="5bbf4923faf099a3515a40d9b0e6e6e32c890ef6cd7a8a120657c2f49d2341fe"
     data-almefy-auth-url="/path/to/auth-controller"></div>

<!-- Load the JavaScript library -->
<script src="https://cdn.almefy.com/js/almefy-0.8.5.js"
        integrity="sha384-W3aXuZP3IQ2Z6PUhHnlF1u1vae7lPHB3JynDJTg0OULfiaLhHmHM3vwOrDhIe6LU"
        crossorigin="anonymous"></script>
```

### Authentication

The authentication controller configured in the `data-alemfy-auth-url` will receive the `X-Almefy-Authorization` header
from the Almefy API. The first thing needs to be done inside the controller is extracting the token from the header and
decode it (it is also verified).

```js
// Get the JWT from header
$jwt = $request->headers->get('X-Almefy-Authorization');

// decode it
$token = $client->decodeJwt($jwt);
```
_Notice: The JWT is provided using the `X-Almefy-Authorization` header for compatibility reasons,
because existing frameworks could use the standard `Authorization: Bearer ...` header._

Next you should check if the user trying to authenticate is in your own identity management system and allowed to
authenticate. This is your own business logic, thus just as an example:

```js
// $userRepository is any PHP class used for database queries 
const user = userRepository.retrieveByUsername(token.getIdentifier());

// Check any internal business logic
if (user.isEnabled() && user.isSubscriptionActive()) {
    //your logic here to login the user
    //no password check needed
}
```

The last and important step is to verify and confirm the authentication attempt on the Almefy system:

```js
if (!$client->verifyToken($token)) {
    // Authentication attempt could not be verified or is invalid
    return false;
}
```

_Notice: For security reasons any network or server error will always return false._

At this stage you can authenticate the user by setting up session variables etc. and redirect him to the protected area.

### License
The Almefy Node SDK is licensed under the Apache License, version 2.0.
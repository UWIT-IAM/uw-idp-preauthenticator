UW IdP preauthenticator

*NOTE*: This is no longer used by UW.  The task is now done with a post-authn intercept.

This app intercepts shib logins from google (via Apache rewrite) and verifies that the user has a google account prior to continuing on to the shib login.
If no account found the user is redirected to create one.  After that the login continues.

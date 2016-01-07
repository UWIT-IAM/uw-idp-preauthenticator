UW IdP preauthenticator

This app intercepts shib logins from google (via Apache rewrite) and verifies that the user has a google account prior to continuing on to the shib login.
If no account found the user is redirected to create one.  After that the login continues.

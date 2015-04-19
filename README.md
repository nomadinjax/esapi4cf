OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
=
This project is part of the Open Web Application Security Project (OWASP) Enterprise Security API (ESAPI) project. For details, please see http://www.owasp.org/index.php/ESAPI.<br>

Copyright (c) 2011 - The OWASP Foundation<br>

The ESAPI is published by OWASP under the BSD license. You should read and accept the LICENSE before you use, modify, and/or redistribute this software.<br>

ABOUT
-
ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications. The ESAPI libraries are designed to make it easier for programmers to retrofit security into existing applications. The ESAPI libraries also serve as a solid foundation for new development. Allowing for language-specific differences, all OWASP ESAPI versions have the same basic design:
- **There is a set of security control interfaces.** They define for example types of parameters that are passed to types of security controls.
- **There is a reference implementation for each security control.** The logic is not organization‐specific and the logic is not application‐specific. An example: string‐based input validation.
- **There are optionally your own implementations for each security control.** There may be application logic contained in these classes which may be developed by or for your organization. An example: enterprise authentication.

This project source code is licensed under the BSD license, which is very permissive and about as close to public domain as is possible. The project documentation is licensed under the Creative Commons license. You can use or modify ESAPI however you want, even include it in commercial products.

GETTING STARTED
-
Adding ESAPI4CF to your CF application is very simple and even more so now in v2 and can be accomplished with just a few lines of code.<br>

To get started, generate a new random master key and master salt using <localhost>/esapi4cf/utilities/secretKeyGenerator.cfm.

Now we will initialize ESAPI inside your onApplicationStart() method...
```
application.ESAPI = new org.owasp.esapi.ESAPI({
	"Encryptor": {
		"MasterKey": "my generated master key",
		"MasterSalt": "my generated master salt"
	}
});
```
Some features of ESAPI require access to the HTTP request and HTTP response, so register them with ESAPI in your onRequestStart() method...
```
application.ESAPI.httpUtilities().setCurrentHTTP(getPageContext().getRequest(), getPageContext().getResponse());
```
Now your set! You will now have access to ESAPI and all of its modules.<br>

**Some examples:**<br>

Want an application specific logger to log data audits and event statuses to:
```
var logger = application.ESAPI.getLogger(application.name & "-Logger");
logger.info(logger.SECURITY_AUDIT, "Data changed!");
```
Want to authenticate and persist a user across requests:
```
application.ESAPI.authenticator().login();
```

Want to see if the current user is logged in:
```
application.ESAPI.authenticator().getCurrentUser().isLoggedIn();
```
Or you can see if the current user is anonymous (not logged in):
```
application.ESAPI.authenticator().getCurrentUser().isAnonymous();
```

Want to change the current user password:
```
application.ESAPI.authenticator().getCurrentUser().changePassword(currentPassword, newPassword, confirmNewPassword);
```

Want to see if the current user has a permission:
```
application.ESAPI.accessController().isAuthorizedForData(action="edit", data=yourData);
```

Want to encode output to prevent cross-site scripting (XSS):
```
application.ESAPI.encoder().encodeForHTML(input);
```

Want to use Anti-Samy to cleanse rich text input so malicious markup does not get into your application:
```
application.ESAPI.validator().getValidSafeHTML(context="myContext", input=myRichTextValue, maxLength=65536, allowNull=true);
```

Want to encrypt a string:
```
application.ESAPI.encryptor().encryptString(value);
```
Or a shortcut to encrypt an entire query string:
```
application.ESAPI.httpUtilities().encryptQueryString(qs);
```

And this is only a fraction of what ESAPI4CF can do to make your web application more secure and it can do it much easier than any other library out there!

EXTENSIBILITY
-
All ESAPI4CF modules can be extended so you can add your own features or override the default implementations.  If, for example, you find that you want implement your own password complexity rules, you can extend the Authenticator implementation and override the **verifyPasswordStrength** method with your own.  Then you simply need to tell ESAPI to use your Authenticator implementation instead of the default.  You do this in your onApplicationStart right after the ESAPI initialization.
```
application.ESAPI = new org.owasp.esapi.ESAPI({
	"ESAPI": {
		"Authenticator": "CFCpathToMyAuthenticatorInstance",
	}
});
```

You no longer need to extended the Authenitcator or AccessController in order to hook ESAPI into your DB model.  As of v2 you can now accomplish this without extending by the use the the ESAPIAdaptor.  The Adaptor simply needs to implement the org.owasp.esapi.Adapter interface.

Or use the provided ESAPI interfaces to create your own implementation entirely.  The choice is yours!

All of the error and log messages generated by ESAPI4CF are resource bundled.  This means the user messages can be customized without altering the code.  This also means you can translate the user messages to any language you wish.

DOCUMENTATION
-
Compatibility information, setup, tutorials, API reference, and links to latest download are available here:<br>
http://damonmiller.github.io/esapi4cf/

RELEASE NOTES
-
Information on bug fixes and improvements for each release are available here:<br>
https://github.com/damonmiller/esapi4cf/releases

ISSUES
-
You can find known issues or report new issues here:<br>
https://github.com/damonmiller/esapi4cf/issues

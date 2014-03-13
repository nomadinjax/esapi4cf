OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
=
This project is part of the Open Web Application Security Project (OWASP) Enterprise Security API (ESAPI) project. For details, please see http://www.owasp.org/index.php/ESAPI.<br>

Copyright (c) 2011-2014, The OWASP Foundation<br>

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
Adding ESAPI4CF to your CF application is very simple and can be accomplished with just a few lines of code.<br>

Let's start with adding one line to your onApplicationStart() method...
```
application.ESAPI = new org.owasp.esapi.ESAPI("/WEB-INF/esapi-resources/");
```
Some features of ESAPI require access to the HTTP request and HTTP response, so register them with ESAPI in your onRequestStart() method...
```
application.ESAPI.httpUtilities().setCurrentHTTP(getPageContext().getRequest(), getPageContext().getResponse());
```
Now your set! You will now have access to ESAPI and all of its modules.<br>

**Some examples:**<br>

Want to validate the HTTP request to check for possible intrusions:
```
application.ESAPI.validator().assertIsValidHTTPRequest();
```
Want to authenticate and persist a users across requests:
```
application.ESAPI.authenticator().login(httpRequest=request, httpResponse=response);
```

Want to see if a user is logged in:
```
application.ESAPI.authenticator().getCurrentUser().isLoggedIn();
```

Want to check a user permission:
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

EXTENSIBILITY
-
All ESAPI4CF modules can be extended so you can add your own features or override the default implementations.  If, for example, you find that you want implement your own password complexity rules, you can extend the Authenticator implementation and override the **verifyPasswordStrength** method with your own.  Then you simply need to tell ESAPI to use your Authenticator implementation instead of the default.  You do this in your onApplicationStart right after the ESAPI initialization.
```
application.ESAPI = new org.owasp.esapi.ESAPI("/WEB-INF/esapi-resources/");
application.ESAPI.setAuthenticator(myAuthenticatorInstance);
```

Or use the provided ESAPI interfaces to create your own implementation entirely.  The choice is yours!

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

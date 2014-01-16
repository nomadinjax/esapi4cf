ESAPI4CF
=
OWASP Enterprise Security API (ESAPI)<br>
OWASP ESAPI for ColdFusion/CFML Project<br>
https://owasp.org/index.php/ESAPI<br>

ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications. The ESAPI libraries are designed to make it easier for programmers to retrofit security into existing applications. The ESAPI libraries also serve as a solid foundation for new development. Allowing for language-specific differences, all OWASP ESAPI versions have the same basic design:
- **There is a set of security control interfaces.** They define for example types of parameters that are passed to types of security controls.
- **There is a reference implementation for each security control.** The logic is not organization‐specific and the logic is not application‐specific. An example: string‐based input validation.
- **There are optionally your own implementations for each security control.** There may be application logic contained in these classes which may be developed by or for your organization. An example: enterprise authentication.

This project source code is licensed under the BSD license, which is very permissive and about as close to public domain as is possible. The project documentation is licensed under the Creative Commons license. You can use or modify ESAPI however you want, even include it in commercial products.

GETTING STARTED
-
Adding ESAPI4CF to your ColdFusion application can be as simple as just one line of code...
```
application.ESAPI = new org.owasp.esapi.ESAPI("/WEB-INF/esapi-resources/");
```
...or choose to implement your own components based on the provided interfaces.

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

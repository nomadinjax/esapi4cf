ESAPI4CF
========
OWASP Enterprise Security API (ESAPI)

OWASP ESAPI for ColdFusion/CFML Project

License: BSD license

https://owasp.org/index.php/ESAPI


Purpose: ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications. The ESAPI libraries are designed to make it easier for programmers to retrofit security into existing applications. The ESAPI libraries also serve as a solid foundation for new development. Allowing for language-specific differences, all OWASP ESAPI versions have the same basic design:
- There is a set of security control interfaces. They define for example types of parameters that are passed to types of security controls.
- There is a reference implementation for each security control. The logic is not organization‐specific and the logic is not application‐specific. An example: string‐based input validation.
- There are optionally your own implementations for each security control. There may be application logic contained in these classes which may be developed by or for your organization. An example: enterprise authentication.

More info: http://damonmiller.github.io/esapi4cf/


RELEASE NOTES
=============

1.0.1a - 2013-09-02
- fixes due to issues found in some real world testing
- [Issue 32] FileBasedAuthenticator#login - try/catch around isSecureChannel that will never catch
- [Issue 33] DefaultValidator#assertIsValidHTTPRequest - error cookie.getValue(), should be httpCookie variable
- [Issue 34] setResourceDirectory value not being picked up
- [Issue 27] Get valid test cases for 'IntegerAccessReferenceMapTest'

1.0.0a - 2013-08-19
- Initial alpha release
- Majority feature complete
- file upload validation not completed (see Issue 22)
- Outstanding unit tests not passing
- Railo4: 10 failures; 71 errors (see Issue 28)
- CF10: 11 failures; 7 errors
- CF9: 11 failures; 7 errors
- CF8: 8 failures; 8 errors
- Still requires real-world testing

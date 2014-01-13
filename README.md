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
v1.1+
https://github.com/damonmiller/esapi4cf/releases

v1.0.3a - 2013-10-18
- fixed SafeSession#getAttributeNames exception 'hasNext' not defined
- ValidateErrorList#errors() was not returning an array
- [Issue #20] none of the AccessController unit tests were passing - all now pass for all supported CFML versions
- Railo 4.1 compatibility - with and without Null support

v1.0.2a - 2013-09-13
- fixes due to issues found in some real world testing
- [Issue #35] DefaultSecurityConfiguration exception "Complex object types cannot be converted to simple values." Line 265
- [Issue #30] getValidDate returntype is 'String' - should allow for Date or empty string
- [Issue #37] getSecurity method needs to be public
- [Issue #36] SafeRequest - HTTPParameterName and HTTPParameterValue had hard-coded maxlengths
- fixed undefined value error in SafeRequest.getHeader

v1.0.1a - 2013-09-02
- fixes due to issues found in some real world testing
- [Issue #32] FileBasedAuthenticator#login - try/catch around isSecureChannel that will never catch
- [Issue #33] DefaultValidator#assertIsValidHTTPRequest - error cookie.getValue(), should be httpCookie variable
- [Issue #34] setResourceDirectory value not being picked up
- [Issue #27] Get valid test cases for 'IntegerAccessReferenceMapTest'

v1.0.0a - 2013-08-19
- Initial alpha release
- Majority feature complete
- file upload validation not completed (see Issue 22)

Outstanding unit tests not passing
- Railo4: 10 failures; 71 errors (see Issue 28)
- CF10: 11 failures; 7 errors
- CF9: 11 failures; 7 errors
- CF8: 8 failures; 8 errors
- Still requires real-world testing

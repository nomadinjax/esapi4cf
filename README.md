esapi4cf
========
OWASP Enterprise Security API (ESAPI)
OWASP ESAPI for ColdFusion/CFML Project
Purpose: This is the ColdFusion/CFML language version of OWASP ESAPI.
= The current release of this project *is not* suitable for production use =
License: BSD license
https://www.owasp.org/index.php/Category:OWASP_Enterprise_Security_API#tab=ColdFusion.2FCFML


*** SETUP/USAGE ***

Setup:
1. Ensure that J2EE session variables be enabled! You will not be able to authenticate if this is disabled.
2. The cfesapi folder should sit at the webroot level.
3. Copy /esapi4cf/esapi/esapi-2.0.1.jar and selected files from /esapi4cf/esapi/libs/ to your lib folder (see compatibility below).
4. Restart ColdFusion.
NOTE: there are folders included with CFESAPI that you will want to exclude from your production environment

Tests:
- You will need to create an 'esapi' folder under your User Home directory so the users.txt file can be written to disk i.e. C:\Users\myusername\esapi\
- You can run the MXUnit tests using: /esapi4cf/test/TestSuite.cfm

Demos:
- See the /esapi4cf/demo/ for basic examples of implementation. **Be sure to have https setup else you can't login.**

Implementation:
- You can extend any of the default implementations to overwrite the methods you need
 and/or
- You can create new implementations that implement the provided interfaces

How:
- Copy the /esapi4cf/esapi/configuration/esapi/ folder to a location within your CF application and make changes to your copy of the config files
- ESAPI.properties
	- IMPORTANT: Run /esapi4cf/org/owasp/esapi/reference/crypto/JavaEncryptor.cfm to calculate your *own* Encryptor.MasterKey and Encryptor.MasterSalt values
	- Update the component paths with the location of your implementation components
	- Modify other configs as needed
- Include the /esapi4cf/helpers/ESAPI.cfm in your application
- Call the filters provided by CFESAPI to secure and authenticate each request.
- See demos for examples

Tips:
- You can determine whether unlimited strength crypto is installed by running: /esapi4cf/test/org/owasp/esapi/reference/crypto/CryptoPolicy.cfm
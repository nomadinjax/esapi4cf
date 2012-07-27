<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 --->
<cfsetting requesttimeout="60">
<cfscript>
	System = createObject( "java", "java.lang.System" );
	instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();

	System.out.println( "INITIALIZING ALL TESTS" );

	// The following property must be set in order for the tests to find the resources directory
	System.setProperty( "cfesapi.org.owasp.esapi.resources", "/cfesapi/test/resources" );
	System.setProperty( "basedir", expandPath("../../../../") );
</cfscript>

<!--- clear the User file to prep for tests --->
<cfset filePath = instance.ESAPI.securityConfiguration().getResourceDirectory() & "users.txt"/>
<cfset writer = ""/>
<cfset writer &= "## This is the user file associated with the ESAPI library from http://www.owasp.org" & chr( 13 ) & chr( 10 )/>
<cfset writer &= "## accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount" & chr( 13 ) & chr( 10 )/>
<cfset writer &= chr( 13 ) & chr( 10 )/>
<cffile action="write" file="#expandPath(filePath)#" output="#writer#"/>

<cfscript>
	suite = createObject( "component", "mxunit.framework.TestSuite" ).TestSuite();
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.DefaultSecurityConfigurationTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.LoggerTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.SafeFileTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.UserTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.ESAPITest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.RandomizerTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.AccessControllerTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.HTTPUtilitiesTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.ValidatorTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.EncryptorTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.IntrusionDetectorTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.AccessReferenceMapTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.IntegerAccessReferenceMapTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.ExecutorTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.EncoderTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.EncryptedPropertiesTest" );
	suite.addAll( "cfesapi.test.org.owasp.esapi.reference.AuthenticatorTest" );

	// exceptions
	suite.addAll( "cfesapi.test.org.owasp.esapi.errors.EnterpriseSecurityExceptionTest" );

	// filters
	suite.addAll( "cfesapi.test.org.owasp.esapi.filters.ESAPIFilterTest" );

	startTestSuiteRunTime = getTickCount();

	results = suite.run();
	writeOutput( results.getResultsOutput( "html" ) );

	// Unset these properties so they do not interfere with other Unit Tests
	System.setProperty( "cfesapi.org.owasp.esapi.resources", "" );
	System.setProperty( "basedir", "" );

	writeOutput( "<p>Total Test Time: #(getTickCount() - startTestSuiteRunTime) / 1000# seconds</p><br/>" );
</cfscript>

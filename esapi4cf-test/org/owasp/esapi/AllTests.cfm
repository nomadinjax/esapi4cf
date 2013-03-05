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
 * @author Damon Miller
 * @created 2011
 --->
<cfsetting requesttimeout="60">
<cfscript>
	System = createObject( "java", "java.lang.System" );
	instance.ESAPI = createObject( "component", "esapi4cf.org.owasp.esapi.ESAPI" ).init();

	System.out.println( "INITIALIZING ALL TESTS" );

	suite = createObject( "component", "mxunit.framework.TestSuite" ).TestSuite();
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.DefaultSecurityConfigurationTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.LoggerTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.SafeFileTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.UserTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.ESAPITest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.RandomizerTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.AccessControllerTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.HTTPUtilitiesTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.ValidatorTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.EncryptorTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.IntrusionDetectorTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.AccessReferenceMapTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.IntegerAccessReferenceMapTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.ExecutorTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.EncoderTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.EncryptedPropertiesTest" );
	suite.addAll( "esapi4cf-test.org.owasp.esapi.reference.AuthenticatorTest" );

	// exceptions
	suite.addAll( "esapi4cf-test.org.owasp.esapi.errors.EnterpriseSecurityExceptionTest" );

	// filters
	suite.addAll( "esapi4cf-test.org.owasp.esapi.filters.ESAPIFilterTest" );

	startTestSuiteRunTime = getTickCount();

	results = suite.run();
	writeOutput( results.getResultsOutput( "html" ) );
	writeOutput( "<p>Total Test Time: #(getTickCount() - startTestSuiteRunTime) / 1000# seconds</p><br/>" );
</cfscript>

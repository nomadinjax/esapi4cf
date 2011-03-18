<!--- takes awhile to run all these tests (FileIO w/ users.txt) --->
<cfsetting requesttimeout="300" />
<cfscript>
	testSuite = createObject("component","mxunit.framework.TestSuite").TestSuite();
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CipherSpecTest");											// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CipherTextSerializerTest");								// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CipherTextTest");											// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CryptoHelperTest");										// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.PlainTextTest");											// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.errors.EnterpriseSecurityExceptionTest");						// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.filters.SafeRequestTest");										// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoaderTest");	//
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.accesscontrol.AccessControllerTest");					// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.crypto.EncryptorTest");								// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.validation.StringValidationRuleTest");					// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.AccessController1Test");								// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.AuthenticatorTest");									// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.DefaultSecurityConfigurationTest");					// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.EncoderTest");											// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.ExecutorTest");										//
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.HTTPUtilitiesTest");									// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.IntrusionDetectorTest");								// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.JavaLoggerTest");										// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.Log4JLoggerTest");										// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.RandomizerTest");										// Test - Class
	//testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.SafeFileTest");										//
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.UserTest");											// Test
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.ValidatorTest");										// Test - Class - Interface
	results = testSuite.run();
	writeOutput(results.getResultsOutput('html'));
</cfscript>

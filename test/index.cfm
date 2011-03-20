<!--- takes awhile to run all these tests (FileIO w/ users.txt) --->
<cfsetting requesttimeout="300" />
<cfscript>
	testSuite = createObject("component","mxunit.framework.TestSuite").TestSuite();
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CipherSpecTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CipherTextSerializerTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CipherTextTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.CryptoHelperTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.crypto.PlainTextTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.errors.EnterpriseSecurityExceptionTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.filters.SafeRequestTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoaderTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.accesscontrol.AccessControllerTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.crypto.EncryptorTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.validation.StringValidationRuleTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.AccessController1Test");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.AuthenticatorTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.DefaultSecurityConfigurationTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.EncoderTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.ExecutorTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.HTTPUtilitiesTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.IntrusionDetectorTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.JavaLoggerTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.Log4JLoggerTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.RandomizerTest");
	//testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.SafeFileTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.UserTest");
	testSuite.addAll("cfesapi.test.org.owasp.esapi.reference.ValidatorTest");
	results = testSuite.run();
	writeOutput(results.getResultsOutput('html'));
</cfscript>

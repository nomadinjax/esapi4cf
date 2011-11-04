/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Damon Miller
 * @created 2011
 */
/**
 * The Class LoggerTest.
 */
component JavaLoggerTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
	instance.testCount = 0;
	instance.testLogger = "";

	/**
	 * {@inheritDoc}
	 * @throws Exception
	 */
	
	public void function setUp() {
		structClear(request);
	
		local.tmpConfig = new UnitTestSecurityConfiguration(instance.ESAPI, instance.ESAPI.securityConfiguration());
		local.logFactory = new cfesapi.org.owasp.esapi.reference.JavaLogFactory(instance.ESAPI);
		tmpConfig.setLogImplementation(getMetaData(local.logFactory).name);
		instance.ESAPI.override(local.tmpConfig);
		//This ensures a clean logger between tests
		instance.testLogger = instance.ESAPI.getLogger("test" & instance.testCount++);
		newJava("java.lang.System").out.println("Test logger: " & instance.testLogger.toString());
	}
	
	/**
	 * {@inheritDoc}
	 * @throws Exception
	 */
	
	public void function tearDown() {
		instance.testLogger = "";
		instance.ESAPI.override("");
	
		structClear(request);
	}
	
	/**
	 * Test of logHTTPRequest method, of class org.owasp.esapi.Logger.
	 * 
	 * @throws ValidationException
	 *             the validation exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testLogHTTPRequest() {
		newJava("java.lang.System").out.println("logHTTPRequest");
		local.ignore = ["password", "ssn", "ccn"];
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
		local.logger = instance.ESAPI.getLogger("logger");
		instance.ESAPI.httpUtilities().logHTTPRequest(local.request, local.logger, local.ignore);
		local.request.addParameter("one", "one");
		local.request.addParameter("two", "two1");
		local.request.addParameter("two", "two2");
		local.request.addParameter("password", "jwilliams");
		instance.ESAPI.httpUtilities().logHTTPRequest(local.request, local.logger, local.ignore);
	}
	
	/**
	 * Test of setLevel method of the inner class org.owasp.esapi.reference.JavaLogger that is defined in 
	 * org.owasp.esapi.reference.JavaLogFactory.
	 */
	
	public void function testSetLevel() {
		newJava("java.lang.System").out.println("setLevel");
	
		// The following tests that the default logging level is set to WARNING. Since the default might be changed
		// in the ESAPI security configuration file, these are commented out.
		//       assertTrue(instance.testLogger.isWarningEnabled());
		//       assertFalse(instance.testLogger.isInfoEnabled());
		// First, test all the different logging levels
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").ALL);
		assertTrue(instance.testLogger.isFatalEnabled());
		assertTrue(instance.testLogger.isErrorEnabled());
		assertTrue(instance.testLogger.isWarningEnabled());
		assertTrue(instance.testLogger.isInfoEnabled());
		assertTrue(instance.testLogger.isDebugEnabled());
		assertTrue(instance.testLogger.isTraceEnabled());
	
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").TRACE);
		assertTrue(instance.testLogger.isFatalEnabled());
		assertTrue(instance.testLogger.isErrorEnabled());
		assertTrue(instance.testLogger.isWarningEnabled());
		assertTrue(instance.testLogger.isInfoEnabled());
		assertTrue(instance.testLogger.isDebugEnabled());
		assertTrue(instance.testLogger.isTraceEnabled());
	
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").DEBUG);
		assertTrue(instance.testLogger.isFatalEnabled());
		assertTrue(instance.testLogger.isErrorEnabled());
		assertTrue(instance.testLogger.isWarningEnabled());
		assertTrue(instance.testLogger.isInfoEnabled());
		assertTrue(instance.testLogger.isDebugEnabled());
		assertFalse(instance.testLogger.isTraceEnabled());
	
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").INFO);
		assertTrue(instance.testLogger.isFatalEnabled());
		assertTrue(instance.testLogger.isErrorEnabled());
		assertTrue(instance.testLogger.isWarningEnabled());
		assertTrue(instance.testLogger.isInfoEnabled());
		assertFalse(instance.testLogger.isDebugEnabled());
		assertFalse(instance.testLogger.isTraceEnabled());
	
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").WARNING);
		assertTrue(instance.testLogger.isFatalEnabled());
		assertTrue(instance.testLogger.isErrorEnabled());
		assertTrue(instance.testLogger.isWarningEnabled());
		assertFalse(instance.testLogger.isInfoEnabled());
		assertFalse(instance.testLogger.isDebugEnabled());
		assertFalse(instance.testLogger.isTraceEnabled());
	
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").ERROR);
		assertTrue(instance.testLogger.isFatalEnabled());
		assertTrue(instance.testLogger.isErrorEnabled());
		assertFalse(instance.testLogger.isWarningEnabled());
		assertFalse(instance.testLogger.isInfoEnabled());
		assertFalse(instance.testLogger.isDebugEnabled());
		assertFalse(instance.testLogger.isTraceEnabled());
	
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").FATAL);
		assertTrue(instance.testLogger.isFatalEnabled());
		assertFalse(instance.testLogger.isErrorEnabled());
		assertFalse(instance.testLogger.isWarningEnabled());
		assertFalse(instance.testLogger.isInfoEnabled());
		assertFalse(instance.testLogger.isDebugEnabled());
		assertFalse(instance.testLogger.isTraceEnabled());
	
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").OFF);
		assertFalse(instance.testLogger.isFatalEnabled());
		assertFalse(instance.testLogger.isErrorEnabled());
		assertFalse(instance.testLogger.isWarningEnabled());
		assertFalse(instance.testLogger.isInfoEnabled());
		assertFalse(instance.testLogger.isDebugEnabled());
		assertFalse(instance.testLogger.isTraceEnabled());
	
		//Now test to see if a change to the logging level in one log affects other logs
		local.newLogger = instance.ESAPI.getLogger("test_num2");
		instance.testLogger.setLevel(newJava("org.owasp.esapi.Logger").OFF);
		local.newLogger.setLevel(newJava("org.owasp.esapi.Logger").INFO);
		assertFalse(instance.testLogger.isFatalEnabled());
		assertFalse(instance.testLogger.isErrorEnabled());
		assertFalse(instance.testLogger.isWarningEnabled());
		assertFalse(instance.testLogger.isInfoEnabled());
		assertFalse(instance.testLogger.isDebugEnabled());
		assertFalse(instance.testLogger.isTraceEnabled());
	
		assertTrue(local.newLogger.isFatalEnabled());
		assertTrue(local.newLogger.isErrorEnabled());
		assertTrue(local.newLogger.isWarningEnabled());
		assertTrue(local.newLogger.isInfoEnabled());
		assertFalse(local.newLogger.isDebugEnabled());
		assertFalse(local.newLogger.isTraceEnabled());
	}
	
	/**
	 * Test of info method, of class org.owasp.esapi.Logger.
	 */
	
	public void function testInfo() {
		newJava("java.lang.System").out.println("info");
		instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message");
		instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message", "");
		instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "%3escript%3f test message", "");
		instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "<script> test message", "");
	}
	
	/**
	 * Test of trace method, of class org.owasp.esapi.Logger.
	 */
	
	public void function testTrace() {
		newJava("java.lang.System").out.println("trace");
		instance.testLogger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message trace");
		instance.testLogger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message trace", "");
	}
	
	/**
	 * Test of debug method, of class org.owasp.esapi.Logger.
	 */
	
	public void function testDebug() {
		newJava("java.lang.System").out.println("debug");
		instance.testLogger.debug(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message debug");
		instance.testLogger.debug(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message debug", "");
	}
	
	/**
	 * Test of error method, of class org.owasp.esapi.Logger.
	 */
	
	public void function testError() {
		newJava("java.lang.System").out.println("error");
		instance.testLogger.error(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message error");
		instance.testLogger.error(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message error", "");
	}
	
	/**
	 * Test of warning method, of class org.owasp.esapi.Logger.
	 */
	
	public void function testWarning() {
		newJava("java.lang.System").out.println("warning");
		instance.testLogger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message warning");
		instance.testLogger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message warning", "");
	}
	
	/**
	 * Test of fatal method, of class org.owasp.esapi.Logger.
	 */
	
	public void function testFatal() {
		newJava("java.lang.System").out.println("fatal");
		instance.testLogger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message fatal");
		instance.testLogger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message fatal", "");
	}
	
	/**
	 * Test of always method, of class org.owasp.esapi.Logger.
	 */
	
	public void function testAlways() {
		newJava("java.lang.System").out.println("always");
		instance.testLogger.always(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message always 1 (SECURITY_SUCCESS)");
		instance.testLogger.always(newJava("org.owasp.esapi.Logger").SECURITY_AUDIT, "test message always 2 (SECURITY_AUDIT)");
		instance.testLogger.always(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message always 3 (SECURITY_SUCCESS)", "");
		instance.testLogger.always(newJava("org.owasp.esapi.Logger").SECURITY_AUDIT, "test message always 4 (SECURITY_AUDIT)", "");
		try {
			throw(object=newJava("java.lang.RuntimeException").init("What? You call that a 'throw'? My grandmother throws better than that and she's been dead for more than 10 years!"));
		}
		catch(java.lang.RuntimeException rtex) {
			instance.testLogger.always(newJava("org.owasp.esapi.Logger").SECURITY_AUDIT, "test message always 5", rtex);
		}
	}
	
}
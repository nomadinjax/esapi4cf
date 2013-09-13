<!---
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
--->
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		variables.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();
		variables.testLogger = variables.ESAPI.getLogger("test");
	</cfscript>

	<cffunction access="public" returntype="void" name="testLogHTTPRequest" output="false"
	            hint="Test of logHTTPRequest method, of class org.owasp.esapi.Logger.">

		<cfscript>
			// CF8 requires 'var' at the top
			var ignore = "";
			var httpRequest = "";
			var httpResponse = "";
			var logger = "";

			System.out.println("logHTTPRequest");
			ignore = ["password", "ssn", "ccn"];
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			logger = variables.ESAPI.getLogger("logger");
			variables.ESAPI.httpUtilities().logHTTPRequest(variables.ESAPI.currentRequest(), logger, ignore);
			httpRequest.addParameter("one", "one");
			httpRequest.addParameter("two", "two1");
			httpRequest.addParameter("two", "two2");
			httpRequest.addParameter("password", "jwilliams");
			variables.ESAPI.httpUtilities().logHTTPRequest(variables.ESAPI.currentRequest(), logger, ignore);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetLevel" output="false"
	            hint="Test of setLevel method of the inner class org.owasp.esapi.reference.JavaLogFactory$JavaLogger that is defined in org.owasp.esapi.reference.JavaLogFactory.">

		<cfscript>
			// CF8 requires 'var' at the top
			var newLogger = "";

			System.out.println("setLevel");

			// The following tests that the default logging level is set to WARNING. Since the default might be changed
			// in the ESAPI security configuration file, these are commented out.
			assertTrue(variables.testLogger.isWarningEnabled());
			assertFalse(variables.testLogger.isInfoEnabled());

			// First, test all the different logging levels
			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").ALL);
			assertTrue(variables.testLogger.isFatalEnabled());
			assertTrue(variables.testLogger.isErrorEnabled());
			assertTrue(variables.testLogger.isWarningEnabled());
			assertTrue(variables.testLogger.isInfoEnabled());
			assertTrue(variables.testLogger.isDebugEnabled());
			assertTrue(variables.testLogger.isTraceEnabled());

			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").TRACE);
			assertTrue(variables.testLogger.isFatalEnabled());
			assertTrue(variables.testLogger.isErrorEnabled());
			assertTrue(variables.testLogger.isWarningEnabled());
			assertTrue(variables.testLogger.isInfoEnabled());
			assertTrue(variables.testLogger.isDebugEnabled());
			assertTrue(variables.testLogger.isTraceEnabled());

			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").DEBUG);
			assertTrue(variables.testLogger.isFatalEnabled());
			assertTrue(variables.testLogger.isErrorEnabled());
			assertTrue(variables.testLogger.isWarningEnabled());
			assertTrue(variables.testLogger.isInfoEnabled());
			assertTrue(variables.testLogger.isDebugEnabled());
			assertFalse(variables.testLogger.isTraceEnabled());

			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").INFO);
			assertTrue(variables.testLogger.isFatalEnabled());
			assertTrue(variables.testLogger.isErrorEnabled());
			assertTrue(variables.testLogger.isWarningEnabled());
			assertTrue(variables.testLogger.isInfoEnabled());
			assertFalse(variables.testLogger.isDebugEnabled());
			assertFalse(variables.testLogger.isTraceEnabled());

			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").WARNING);
			assertTrue(variables.testLogger.isFatalEnabled());
			assertTrue(variables.testLogger.isErrorEnabled());
			assertTrue(variables.testLogger.isWarningEnabled());
			assertFalse(variables.testLogger.isInfoEnabled());
			assertFalse(variables.testLogger.isDebugEnabled());
			assertFalse(variables.testLogger.isTraceEnabled());

			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").ERROR);
			assertTrue(variables.testLogger.isFatalEnabled());
			assertTrue(variables.testLogger.isErrorEnabled());
			assertFalse(variables.testLogger.isWarningEnabled());
			assertFalse(variables.testLogger.isInfoEnabled());
			assertFalse(variables.testLogger.isDebugEnabled());
			assertFalse(variables.testLogger.isTraceEnabled());

			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").FATAL);
			assertTrue(variables.testLogger.isFatalEnabled());
			assertFalse(variables.testLogger.isErrorEnabled());
			assertFalse(variables.testLogger.isWarningEnabled());
			assertFalse(variables.testLogger.isInfoEnabled());
			assertFalse(variables.testLogger.isDebugEnabled());
			assertFalse(variables.testLogger.isTraceEnabled());

			variables.testLogger.setLevel(newJava("org.owasp.esapi.Logger").OFF);
			assertFalse(variables.testLogger.isFatalEnabled());
			assertFalse(variables.testLogger.isErrorEnabled());
			assertFalse(variables.testLogger.isWarningEnabled());
			assertFalse(variables.testLogger.isInfoEnabled());
			assertFalse(variables.testLogger.isDebugEnabled());
			assertFalse(variables.testLogger.isTraceEnabled());

			//Now test to see if a change to the logging level in one log affects other logs
			newLogger = variables.ESAPI.getLogger("test_num2");
			newLogger.setLevel(newJava("org.owasp.esapi.Logger").INFO);
			assertFalse(variables.testLogger.isFatalEnabled());
			assertFalse(variables.testLogger.isErrorEnabled());
			assertFalse(variables.testLogger.isWarningEnabled());
			assertFalse(variables.testLogger.isInfoEnabled());
			assertFalse(variables.testLogger.isDebugEnabled());
			assertFalse(variables.testLogger.isTraceEnabled());

			assertTrue(newLogger.isFatalEnabled());
			assertTrue(newLogger.isErrorEnabled());
			assertTrue(newLogger.isWarningEnabled());
			assertTrue(newLogger.isInfoEnabled());
			assertFalse(newLogger.isDebugEnabled());
			assertFalse(newLogger.isTraceEnabled());

			// Set the logging level back to whatever it is configured to be.
			variables.testLogger.setLevel(variables.ESAPI.securityConfiguration().getLogLevel());

			// Normally, the default is Logger.WARNING, but if the default was changed, these tests would fail,
			// so there are commented out for now. But you can enable to test.
			//assertTrue(variables.testLogger.isWarningEnabled());
			//assertTrue(variables.testLogger.isInfoEnabled());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testInfo" output="false"
	            hint="Test of info method, of class org.owasp.esapi.Logger.">

		<cfscript>
			System.out.println("info");
			variables.testLogger.info(getSecurityType("SECURITY_SUCCESS"), true, "test message");
			variables.testLogger.info(getSecurityType("SECURITY_SUCCESS"), true, "test message", "");
			variables.testLogger.info(getSecurityType("SECURITY_SUCCESS"), true, "%3escript%3f test message", "");
			variables.testLogger.info(getSecurityType("SECURITY_SUCCESS"), true, "<script> test message", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testTrace" output="false"
	            hint="Test of trace method, of class org.owasp.esapi.Logger.">

		<cfscript>
			System.out.println("trace");
			variables.testLogger.trace(getSecurityType("SECURITY_SUCCESS"), true, "test message");
			variables.testLogger.trace(getSecurityType("SECURITY_SUCCESS"), true, "test message", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDebug" output="false"
	            hint="Test of debug method, of class org.owasp.esapi.Logger.">

		<cfscript>
			System.out.println("debug");
			variables.testLogger.debug(getSecurityType("SECURITY_SUCCESS"), true, "test message");
			variables.testLogger.debug(getSecurityType("SECURITY_SUCCESS"), true, "test message", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testError" output="false"
	            hint="Test of error method, of class org.owasp.esapi.Logger.">

		<cfscript>
			System.out.println("error");
			variables.testLogger.error(getSecurityType("SECURITY_SUCCESS"), true, "test message");
			variables.testLogger.error(getSecurityType("SECURITY_SUCCESS"), true, "test message", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testWarning" output="false"
	            hint="Test of warning method, of class org.owasp.esapi.Logger.">

		<cfscript>
			System.out.println("warning");
			variables.testLogger.warning(getSecurityType("SECURITY_SUCCESS"), true, "test message");
			variables.testLogger.warning(getSecurityType("SECURITY_SUCCESS"), true, "test message", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testFatal" output="false"
	            hint="Test of fatal method, of class org.owasp.esapi.Logger.">

		<cfscript>
			System.out.println("fatal");
			variables.testLogger.fatal(getSecurityType("SECURITY_SUCCESS"), true, "test message");
			variables.testLogger.fatal(getSecurityType("SECURITY_SUCCESS"), true, "test message", "");
		</cfscript>

	</cffunction>

</cfcomponent>
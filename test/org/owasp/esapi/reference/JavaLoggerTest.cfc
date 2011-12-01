<!--- /**
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
 */ --->
<cfcomponent displayname="JavaLoggerTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false" hint="The Class LoggerTest.">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();
		instance.testCount = 0;
		instance.testLogger = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfset var local = {}/>

		<cfscript>
			structClear(request);

			local.tmpConfig = newComponent("cfesapi.test.org.owasp.esapi.reference.UnitTestSecurityConfiguration").init(instance.ESAPI, instance.ESAPI.securityConfiguration());
			local.logFactory = newComponent("cfesapi.org.owasp.esapi.reference.JavaLogFactory").init(instance.ESAPI);
			local.tmpConfig.setLogImplementation(getMetaData(local.logFactory).name);
			instance.ESAPI.override(local.tmpConfig);
			//This ensures a clean logger between tests
			instance.testLogger = instance.ESAPI.getLogger("test" & instance.testCount++);
			newJava("java.lang.System").out.println("Test logger: " & instance.testLogger.toStringESAPI());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			instance.testLogger = "";
			instance.ESAPI.override("");

			structClear(request);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testLogHTTPRequest" output="false"
	            hint="Test of logHTTPRequest method, of class org.owasp.esapi.Logger.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("logHTTPRequest");
			local.ignore = ["password", "ssn", "ccn"];
			local.request = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.response = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.logger = instance.ESAPI.getLogger("logger");
			instance.ESAPI.httpUtilities().logHTTPRequest(local.request, local.logger, local.ignore);
			local.request.addParameter("one", "one");
			local.request.addParameter("two", "two1");
			local.request.addParameter("two", "two2");
			local.request.addParameter("password", "jwilliams");
			instance.ESAPI.httpUtilities().logHTTPRequest(local.request, local.logger, local.ignore);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetLevel" output="false"
	            hint="Test of setLevel method of the inner class org.owasp.esapi.reference.JavaLogger that is defined in org.owasp.esapi.reference.JavaLogFactory.">
		<cfset var local = {}/>

		<cfscript>
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
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testInfo" output="false"
	            hint="Test of info method, of class org.owasp.esapi.Logger.">

		<cfscript>
			newJava("java.lang.System").out.println("info");
			instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message");
			instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message", "");
			instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "%3escript%3f test message", "");
			instance.testLogger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "<script> test message", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testTrace" output="false"
	            hint="Test of trace method, of class org.owasp.esapi.Logger.">

		<cfscript>
			newJava("java.lang.System").out.println("trace");
			instance.testLogger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message trace");
			instance.testLogger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message trace", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDebug" output="false"
	            hint="Test of debug method, of class org.owasp.esapi.Logger.">

		<cfscript>
			newJava("java.lang.System").out.println("debug");
			instance.testLogger.debug(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message debug");
			instance.testLogger.debug(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message debug", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testError" output="false"
	            hint="Test of error method, of class org.owasp.esapi.Logger.">

		<cfscript>
			newJava("java.lang.System").out.println("error");
			instance.testLogger.error(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message error");
			instance.testLogger.error(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message error", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testWarning" output="false"
	            hint="Test of warning method, of class org.owasp.esapi.Logger.">

		<cfscript>
			newJava("java.lang.System").out.println("warning");
			instance.testLogger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message warning");
			instance.testLogger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message warning", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testFatal" output="false"
	            hint="Test of fatal method, of class org.owasp.esapi.Logger.">

		<cfscript>
			newJava("java.lang.System").out.println("fatal");
			instance.testLogger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message fatal");
			instance.testLogger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "test message fatal", "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testAlways" output="false"
	            hint="Test of always method, of class org.owasp.esapi.Logger.">

		<cfscript>
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
		</cfscript>

	</cffunction>

</cfcomponent>
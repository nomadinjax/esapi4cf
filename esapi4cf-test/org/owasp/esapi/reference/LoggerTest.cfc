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
<cfcomponent extends="esapi4cf-test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "esapi4cf.org.owasp.esapi.ESAPI" ).init();
		instance.testLogger = instance.ESAPI.getLogger( "test" );
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear( request );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testLogHTTPRequest" output="false"
	            hint="Test of logHTTPRequest method, of class org.owasp.esapi.Logger.">

		<cfscript>
			var local = {};
			System.out.println( "logHTTPRequest" );
			local.ignore = ["password", "ssn", "ccn"];
			local.request = createObject( "component", "esapi4cf-test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "esapi4cf-test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.logger = instance.ESAPI.getLogger( "logger" );
			instance.ESAPI.httpUtilities().logHTTPRequest( instance.ESAPI.currentRequest(), local.logger, local.ignore );
			local.request.addParameter( "one", "one" );
			local.request.addParameter( "two", "two1" );
			local.request.addParameter( "two", "two2" );
			local.request.addParameter( "password", "jwilliams" );
			instance.ESAPI.httpUtilities().logHTTPRequest( instance.ESAPI.currentRequest(), local.logger, local.ignore );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetLevel" output="false"
	            hint="Test of setLevel method of the inner class org.owasp.esapi.reference.JavaLogger that is defined in org.owasp.esapi.reference.JavaLogFactory.">

		<cfscript>
			var local = {};
			System.out.println( "setLevel" );

			// The following tests that the default logging level is set to WARNING. Since the default might
			//be changed
			// in the ESAPI security configuration file, these are commented out.
			assertTrue( instance.testLogger.isWarningEnabled() );
			assertFalse( instance.testLogger.isInfoEnabled() );

			// First, test all the different logging levels
			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).ALL );
			assertTrue( instance.testLogger.isFatalEnabled() );
			assertTrue( instance.testLogger.isErrorEnabled() );
			assertTrue( instance.testLogger.isWarningEnabled() );
			assertTrue( instance.testLogger.isInfoEnabled() );
			assertTrue( instance.testLogger.isDebugEnabled() );
			assertTrue( instance.testLogger.isTraceEnabled() );

			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).TRACE );
			assertTrue( instance.testLogger.isFatalEnabled() );
			assertTrue( instance.testLogger.isErrorEnabled() );
			assertTrue( instance.testLogger.isWarningEnabled() );
			assertTrue( instance.testLogger.isInfoEnabled() );
			assertTrue( instance.testLogger.isDebugEnabled() );
			assertTrue( instance.testLogger.isTraceEnabled() );

			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).DEBUG );
			assertTrue( instance.testLogger.isFatalEnabled() );
			assertTrue( instance.testLogger.isErrorEnabled() );
			assertTrue( instance.testLogger.isWarningEnabled() );
			assertTrue( instance.testLogger.isInfoEnabled() );
			assertTrue( instance.testLogger.isDebugEnabled() );
			assertFalse( instance.testLogger.isTraceEnabled() );

			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).INFO );
			assertTrue( instance.testLogger.isFatalEnabled() );
			assertTrue( instance.testLogger.isErrorEnabled() );
			assertTrue( instance.testLogger.isWarningEnabled() );
			assertTrue( instance.testLogger.isInfoEnabled() );
			assertFalse( instance.testLogger.isDebugEnabled() );
			assertFalse( instance.testLogger.isTraceEnabled() );

			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).WARNING );
			assertTrue( instance.testLogger.isFatalEnabled() );
			assertTrue( instance.testLogger.isErrorEnabled() );
			assertTrue( instance.testLogger.isWarningEnabled() );
			assertFalse( instance.testLogger.isInfoEnabled() );
			assertFalse( instance.testLogger.isDebugEnabled() );
			assertFalse( instance.testLogger.isTraceEnabled() );

			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).ERROR );
			assertTrue( instance.testLogger.isFatalEnabled() );
			assertTrue( instance.testLogger.isErrorEnabled() );
			assertFalse( instance.testLogger.isWarningEnabled() );
			assertFalse( instance.testLogger.isInfoEnabled() );
			assertFalse( instance.testLogger.isDebugEnabled() );
			assertFalse( instance.testLogger.isTraceEnabled() );

			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).FATAL );
			assertTrue( instance.testLogger.isFatalEnabled() );
			assertFalse( instance.testLogger.isErrorEnabled() );
			assertFalse( instance.testLogger.isWarningEnabled() );
			assertFalse( instance.testLogger.isInfoEnabled() );
			assertFalse( instance.testLogger.isDebugEnabled() );
			assertFalse( instance.testLogger.isTraceEnabled() );

			instance.testLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).OFF );
			assertFalse( instance.testLogger.isFatalEnabled() );
			assertFalse( instance.testLogger.isErrorEnabled() );
			assertFalse( instance.testLogger.isWarningEnabled() );
			assertFalse( instance.testLogger.isInfoEnabled() );
			assertFalse( instance.testLogger.isDebugEnabled() );
			assertFalse( instance.testLogger.isTraceEnabled() );

			//Now test to see if a change to the logging level in one log affects other logs
			local.newLogger = instance.ESAPI.getLogger( "test_num2" );
			local.newLogger.setLevel( getJava( "org.owasp.esapi.Logger" ).INFO );
			assertFalse( instance.testLogger.isFatalEnabled() );
			assertFalse( instance.testLogger.isErrorEnabled() );
			assertFalse( instance.testLogger.isWarningEnabled() );
			assertFalse( instance.testLogger.isInfoEnabled() );
			assertFalse( instance.testLogger.isDebugEnabled() );
			assertFalse( instance.testLogger.isTraceEnabled() );

			assertTrue(local.newLogger.isFatalEnabled());
			assertTrue(local.newLogger.isErrorEnabled());
			assertTrue(local.newLogger.isWarningEnabled());
			assertTrue(local.newLogger.isInfoEnabled());
			assertFalse(local.newLogger.isDebugEnabled());
			assertFalse(local.newLogger.isTraceEnabled());

			// Set the logging level back to whatever it is configured to be.
			instance.testLogger.setLevel( instance.ESAPI.securityConfiguration().getLogLevel() );

			// Normally, the default is Logger.WARNING, but if the default was changed, these tests would
			//fail,
			// so there are commented out for now. But you can enable to test.
			//assertTrue(instance.testLogger.isWarningEnabled());
			//assertTrue(instance.testLogger.isInfoEnabled());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testInfo" output="false"
	            hint="Test of info method, of class org.owasp.esapi.Logger.">

		<cfscript>
			var local = {};
			System.out.println( "info" );
			instance.testLogger.info( getSecurity("SECURITY_SUCCESS"), true, "test message" );
			instance.testLogger.info( getSecurity("SECURITY_SUCCESS"), true, "test message", "" );
			instance.testLogger.info( getSecurity("SECURITY_SUCCESS"), true, "%3escript%3f test message", "" );
			instance.testLogger.info( getSecurity("SECURITY_SUCCESS"), true, "<script> test message", "" );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testTrace" output="false"
	            hint="Test of trace method, of class org.owasp.esapi.Logger.">

		<cfscript>
			var local = {};
			System.out.println( "trace" );
			instance.testLogger.trace( getSecurity("SECURITY_SUCCESS"), true, "test message" );
			instance.testLogger.trace( getSecurity("SECURITY_SUCCESS"), true, "test message", "" );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDebug" output="false"
	            hint="Test of debug method, of class org.owasp.esapi.Logger.">

		<cfscript>
			var local = {};
			System.out.println( "debug" );
			instance.testLogger.debug( getSecurity("SECURITY_SUCCESS"), true, "test message" );
			instance.testLogger.debug( getSecurity("SECURITY_SUCCESS"), true, "test message", "" );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testError" output="false"
	            hint="Test of error method, of class org.owasp.esapi.Logger.">

		<cfscript>
			var local = {};
			System.out.println( "error" );
			instance.testLogger.error( getSecurity("SECURITY_SUCCESS"), true, "test message" );
			instance.testLogger.error( getSecurity("SECURITY_SUCCESS"), true, "test message", "" );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testWarning" output="false"
	            hint="Test of warning method, of class org.owasp.esapi.Logger.">

		<cfscript>
			var local = {};
			System.out.println( "warning" );
			instance.testLogger.warning( getSecurity("SECURITY_SUCCESS"), true, "test message" );
			instance.testLogger.warning( getSecurity("SECURITY_SUCCESS"), true, "test message", "" );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testFatal" output="false"
	            hint="Test of fatal method, of class org.owasp.esapi.Logger.">

		<cfscript>
			var local = {};
			System.out.println( "fatal" );
			instance.testLogger.fatal( getSecurity("SECURITY_SUCCESS"), true, "test message" );
			instance.testLogger.fatal( getSecurity("SECURITY_SUCCESS"), true, "test message", "" );
		</cfscript>

	</cffunction>

</cfcomponent>
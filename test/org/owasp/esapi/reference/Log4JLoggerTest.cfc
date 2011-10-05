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
<cfcomponent extends="cfesapi.test.TestCase" output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");
		Logger = createObject("java", "org.owasp.esapi.Logger");

		instance.testCount = 0;
		instance.testLogger = "";
		//a logger for explicit tests of log4j logging methods
		instance.log4JLogger = "";
		
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(request);

			//override default log configuration in ESAPI.properties to use Log4JLogFactory
			local.tmpConfig = createObject("component", "UnitTestSecurityConfiguration").init(instance.ESAPI, instance.ESAPI.securityConfiguration());
	        local.tmpConfig.setLogImplementation( getMetaData(createObject("component", "cfesapi.org.owasp.esapi.reference.Log4JLogFactory")).name);
	        instance.ESAPI.override(local.tmpConfig);
	    	// This ensures a clean logger between tests
	    	instance.testLogger = instance.ESAPI.getLogger( "test ExampleExtendedLog4JLogFactory: " & instance.testCount++ );
	    	System.out.println("Test ExampleExtendedLog4JLogFactory logger: " & instance.testLogger.toString());

			//declare this one as Log4JLogger to be able to use Log4J logging methods
			instance.log4JLogger = instance.ESAPI.getLogger( "test Log4JLogFactory: " & instance.testCount);
			System.out.println("Test Log4JLogFactory logger: " & instance.log4JLogger.toString());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			instance.testLogger = "";
			instance.log4JLogger = "";
			instance.ESAPI.override("");

			structClear(request);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testLogHTTPRequest" output="false" hint="Test of logHTTPRequest method, of class org.owasp.esapi.Logger.">
		<cfscript>
			System.out.println("logHTTPRequest");
			local.ignore = ["password","ssn","ccn"];
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse");
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.logger = instance.ESAPI.getLogger("logger");
			instance.ESAPI.httpUtilities().logHTTPRequest( local.request, local.logger, local.ignore );
			local.request.addParameter("one","one");
			local.request.addParameter("two","two1");
			local.request.addParameter("two","two2");
			local.request.addParameter("password","jwilliams");
			instance.ESAPI.httpUtilities().logHTTPRequest( local.request, local.logger, local.ignore );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetLevel" output="false" hint="Test of setLevel method of the inner class org.owasp.esapi.reference.JavaLogger that is defined in org.owasp.esapi.reference.JavaLogFactory.">
		<cfscript>
	        System.out.println("setLevel");

	        // The following tests that the default logging level is set to WARNING. Since the default might be changed
	        // in the ESAPI security configuration file, these are commented out.
	//       	assertTrue(instance.testLogger.isWarningEnabled());
	//       	assertFalse(instance.testLogger.isInfoEnabled());

	        // First, test all the different logging levels
	        instance.testLogger.setLevel( Logger.ALL );
	    	assertTrue(instance.testLogger.isFatalEnabled());
	       	assertTrue(instance.testLogger.isErrorEnabled());
	       	assertTrue(instance.testLogger.isWarningEnabled());
	       	assertTrue(instance.testLogger.isInfoEnabled());
	       	assertTrue(instance.testLogger.isDebugEnabled());
	       	assertTrue(instance.testLogger.isTraceEnabled());

	       	instance.testLogger.setLevel( Logger.TRACE );
	    	assertTrue(instance.testLogger.isFatalEnabled());
	       	assertTrue(instance.testLogger.isErrorEnabled());
	       	assertTrue(instance.testLogger.isWarningEnabled());
	       	assertTrue(instance.testLogger.isInfoEnabled());
	       	assertTrue(instance.testLogger.isDebugEnabled());
	       	assertTrue(instance.testLogger.isTraceEnabled());

	       	instance.testLogger.setLevel( Logger.DEBUG );
	    	assertTrue(instance.testLogger.isFatalEnabled());
	       	assertTrue(instance.testLogger.isErrorEnabled());
	       	assertTrue(instance.testLogger.isWarningEnabled());
	       	assertTrue(instance.testLogger.isInfoEnabled());
	       	assertTrue(instance.testLogger.isDebugEnabled());
	       	assertFalse(instance.testLogger.isTraceEnabled());

	       	instance.testLogger.setLevel( Logger.INFO );
	    	assertTrue(instance.testLogger.isFatalEnabled());
	       	assertTrue(instance.testLogger.isErrorEnabled());
	       	assertTrue(instance.testLogger.isWarningEnabled());
	       	assertTrue(instance.testLogger.isInfoEnabled());
	       	assertFalse(instance.testLogger.isDebugEnabled());
	       	assertFalse(instance.testLogger.isTraceEnabled());

	       	instance.testLogger.setLevel( Logger.WARNING );
	    	assertTrue(instance.testLogger.isFatalEnabled());
	       	assertTrue(instance.testLogger.isErrorEnabled());
	       	assertTrue(instance.testLogger.isWarningEnabled());
	       	assertFalse(instance.testLogger.isInfoEnabled());
	       	assertFalse(instance.testLogger.isDebugEnabled());
	       	assertFalse(instance.testLogger.isTraceEnabled());

	       	instance.testLogger.setLevel( Logger.ERROR );
	    	assertTrue(instance.testLogger.isFatalEnabled());
	       	assertTrue(instance.testLogger.isErrorEnabled());
	       	assertFalse(instance.testLogger.isWarningEnabled());
	       	assertFalse(instance.testLogger.isInfoEnabled());
	       	assertFalse(instance.testLogger.isDebugEnabled());
	       	assertFalse(instance.testLogger.isTraceEnabled());

	       	instance.testLogger.setLevel( Logger.FATAL );
	    	assertTrue(instance.testLogger.isFatalEnabled());
	       	assertFalse(instance.testLogger.isErrorEnabled());
	       	assertFalse(instance.testLogger.isWarningEnabled());
	       	assertFalse(instance.testLogger.isInfoEnabled());
	       	assertFalse(instance.testLogger.isDebugEnabled());
	       	assertFalse(instance.testLogger.isTraceEnabled());

	       	instance.testLogger.setLevel( Logger.OFF );
	    	assertFalse(instance.testLogger.isFatalEnabled());
	       	assertFalse(instance.testLogger.isErrorEnabled());
	       	assertFalse(instance.testLogger.isWarningEnabled());
	       	assertFalse(instance.testLogger.isInfoEnabled());
	       	assertFalse(instance.testLogger.isDebugEnabled());
	       	assertFalse(instance.testLogger.isTraceEnabled());

	       	//Now test to see if a change to the logging level in one log affects other logs
	       	local.newLogger = instance.ESAPI.getLogger( "test_num2" );
	       	instance.testLogger.setLevel( Logger.OFF );
	       	local.newLogger.setLevel( Logger.INFO );
	    	assertFalse(instance.testLogger.isFatalEnabled());
	       	assertFalse(instance.testLogger.isErrorEnabled());
	       	assertFalse(instance.testLogger.isWarningEnabled());
	       	assertFalse(instance.testLogger.isInfoEnabled());
	       	assertFalse(instance.testLogger.isDebugEnabled());
	       	assertFalse(instance.testLogger.isTraceEnabled());

	       	assertTrue(newLogger.isFatalEnabled());
	       	assertTrue(newLogger.isErrorEnabled());
	       	assertTrue(newLogger.isWarningEnabled());
	       	assertTrue(newLogger.isInfoEnabled());
	       	assertFalse(newLogger.isDebugEnabled());
	       	assertFalse(newLogger.isTraceEnabled());
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testLogLevels" output="false" hint="test of loggers without setting explicit log levels (log levels set from log4j.xml configuration)">
		<cfscript>
		local.traceLogger			= instance.ESAPI.getLogger("cfesapi.test.org.owasp.esapi.reference.TestTrace");
		local.debugLogger			= instance.ESAPI.getLogger("cfesapi.test.org.owasp.esapi.reference.TestDebug");
		local.infoLogger			= instance.ESAPI.getLogger("cfesapi.test.org.owasp.esapi.reference.TestInfo");
		local.errorLogger			= instance.ESAPI.getLogger("cfesapi.test.org.owasp.esapi.reference.TestError");
		local.warningLogger			= instance.ESAPI.getLogger("cfesapi.test.org.owasp.esapi.reference.TestWarning");
		local.fatalLogger			= instance.ESAPI.getLogger("cfesapi.test.org.owasp.esapi.reference.TestFatal");
		local.unspecifiedLogger		= instance.ESAPI.getLogger("cfesapi.test.org.owasp.esapi.reference");  //should use package-wide log level configuration (info)

		//local.traceLogger - all log levels should be enabled
		assertTrue(local.traceLogger.isTraceEnabled());
		assertTrue(local.traceLogger.isDebugEnabled());
		assertTrue(local.traceLogger.isInfoEnabled());
		assertTrue(local.traceLogger.isWarningEnabled());
		assertTrue(local.traceLogger.isErrorEnabled());
		assertTrue(local.traceLogger.isFatalEnabled());

		//local.debugLogger - all log levels should be enabled EXCEPT trace
		assertFalse(local.debugLogger.isTraceEnabled());
		assertTrue(local.debugLogger.isDebugEnabled());
		assertTrue(local.debugLogger.isInfoEnabled());
		assertTrue(local.debugLogger.isWarningEnabled());
		assertTrue(local.debugLogger.isErrorEnabled());
		assertTrue(local.debugLogger.isFatalEnabled());

		//local.infoLogger - all log levels should be enabled EXCEPT trace and debug
		assertFalse(local.infoLogger.isTraceEnabled());
		assertFalse(local.infoLogger.isDebugEnabled());
		assertTrue(local.infoLogger.isInfoEnabled());
		assertTrue(local.infoLogger.isWarningEnabled());
		assertTrue(local.infoLogger.isErrorEnabled());
		assertTrue(local.infoLogger.isFatalEnabled());

		//local.warningLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(local.warningLogger.isTraceEnabled());
		assertFalse(local.warningLogger.isDebugEnabled());
		assertFalse(local.warningLogger.isInfoEnabled());
		assertTrue(local.warningLogger.isWarningEnabled());
		assertTrue(local.warningLogger.isErrorEnabled());
		assertTrue(local.warningLogger.isFatalEnabled());

		//local.errorLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(local.errorLogger.isTraceEnabled());
		assertFalse(local.errorLogger.isDebugEnabled());
		assertFalse(local.errorLogger.isInfoEnabled());
		assertFalse(local.errorLogger.isWarningEnabled());
		assertTrue(local.errorLogger.isErrorEnabled());
		assertTrue(local.errorLogger.isFatalEnabled());

		//local.fatalLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(local.fatalLogger.isTraceEnabled());
		assertFalse(local.fatalLogger.isDebugEnabled());
		assertFalse(local.fatalLogger.isInfoEnabled());
		assertFalse(local.fatalLogger.isWarningEnabled());
		assertFalse(local.fatalLogger.isErrorEnabled());
		assertTrue(local.fatalLogger.isFatalEnabled());

		//local.unspecifiedLogger - all log levels should be enabled EXCEPT trace and debug
		assertFalse(local.unspecifiedLogger.isTraceEnabled());
		assertFalse(local.unspecifiedLogger.isDebugEnabled());
		assertTrue(local.unspecifiedLogger.isInfoEnabled());
		assertTrue(local.unspecifiedLogger.isWarningEnabled());
		assertTrue(local.unspecifiedLogger.isErrorEnabled());
		assertTrue(local.unspecifiedLogger.isFatalEnabled());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testLogLevelsWithClass" output="false" hint="test of loggers without setting explicit log levels (log levels set from log4j.xml configuration)">
		<cfscript>
			local.traceLogger			= instance.ESAPI.getLogger(TestTrace.class);
			local.debugLogger			= instance.ESAPI.getLogger(TestDebug.class);
			local.infoLogger			= instance.ESAPI.getLogger(TestInfo.class);
			local.errorLogger			= instance.ESAPI.getLogger(TestError.class);
			local.warningLogger			= instance.ESAPI.getLogger(TestWarning.class);
			local.fatalLogger			= instance.ESAPI.getLogger(TestFatal.class);
			local.unspecifiedLogger		= instance.ESAPI.getLogger(TestUnspecified.class);  //should use package-wide log level configuration (info)
	
			//local.traceLogger - all log levels should be enabled
			assertTrue(local.traceLogger.isTraceEnabled());
			assertTrue(local.traceLogger.isDebugEnabled());
			assertTrue(local.traceLogger.isInfoEnabled());
			assertTrue(local.traceLogger.isWarningEnabled());
			assertTrue(local.traceLogger.isErrorEnabled());
			assertTrue(local.traceLogger.isFatalEnabled());
	
			//local.debugLogger - all log levels should be enabled EXCEPT trace
			assertFalse(local.debugLogger.isTraceEnabled());
			assertTrue(local.debugLogger.isDebugEnabled());
			assertTrue(local.debugLogger.isInfoEnabled());
			assertTrue(local.debugLogger.isWarningEnabled());
			assertTrue(local.debugLogger.isErrorEnabled());
			assertTrue(local.debugLogger.isFatalEnabled());
	
			//local.infoLogger - all log levels should be enabled EXCEPT trace and debug
			assertFalse(local.infoLogger.isTraceEnabled());
			assertFalse(local.infoLogger.isDebugEnabled());
			assertTrue(local.infoLogger.isInfoEnabled());
			assertTrue(local.infoLogger.isWarningEnabled());
			assertTrue(local.infoLogger.isErrorEnabled());
			assertTrue(local.infoLogger.isFatalEnabled());
	
			//local.warningLogger - all log levels should be enabled EXCEPT etc.
			assertFalse(local.warningLogger.isTraceEnabled());
			assertFalse(local.warningLogger.isDebugEnabled());
			assertFalse(local.warningLogger.isInfoEnabled());
			assertTrue(local.warningLogger.isWarningEnabled());
			assertTrue(local.warningLogger.isErrorEnabled());
			assertTrue(local.warningLogger.isFatalEnabled());
	
			//local.errorLogger - all log levels should be enabled EXCEPT etc.
			assertFalse(local.errorLogger.isTraceEnabled());
			assertFalse(local.errorLogger.isDebugEnabled());
			assertFalse(local.errorLogger.isInfoEnabled());
			assertFalse(local.errorLogger.isWarningEnabled());
			assertTrue(local.errorLogger.isErrorEnabled());
			assertTrue(local.errorLogger.isFatalEnabled());
	
			//local.fatalLogger - all log levels should be enabled EXCEPT etc.
			assertFalse(local.fatalLogger.isTraceEnabled());
			assertFalse(local.fatalLogger.isDebugEnabled());
			assertFalse(local.fatalLogger.isInfoEnabled());
			assertFalse(local.fatalLogger.isWarningEnabled());
			assertFalse(local.fatalLogger.isErrorEnabled());
			assertTrue(local.fatalLogger.isFatalEnabled());
	
			//local.unspecifiedLogger - all log levels should be enabled EXCEPT trace and debug
			assertFalse(local.unspecifiedLogger.isTraceEnabled());
			assertFalse(local.unspecifiedLogger.isDebugEnabled());
			assertTrue(local.unspecifiedLogger.isInfoEnabled());
			assertTrue(local.unspecifiedLogger.isWarningEnabled());
			assertTrue(local.unspecifiedLogger.isErrorEnabled());
			assertTrue(local.unspecifiedLogger.isFatalEnabled());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testInfo" output="false" hint="Test of info method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        System.out.println("info");
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "test message" );
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "test message", "" );
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "%3escript%3f test message", "" );
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "<script> test message", "" );
	        
	        instance.log4JLogger.info("test message" );
	        instance.log4JLogger.info("test message", null );
	        instance.log4JLogger.info("%3escript%3f test message", null );
	        instance.log4JLogger.info("<script> test message", null );
	
	        instance.log4JLogger.info(Logger.SECURITY_SUCCESS, "test message" );
	        instance.log4JLogger.info(Logger.SECURITY_SUCCESS, "test message", null );
	        instance.log4JLogger.info(Logger.SECURITY_SUCCESS, "%3escript%3f test message", null );
	        instance.log4JLogger.info(Logger.SECURITY_SUCCESS, "<script> test message", null );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testTrace" output="false" hint="Test of trace method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        System.out.println("trace");
	        instance.testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace" );
	        instance.testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace", "" );
	        
	        instance.log4JLogger.trace(message="test message trace" );
        	instance.log4JLogger.trace(message="test message trace", throwable="" );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testDebug" output="false" hint="Test of debug method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        System.out.println("debug");
	        instance.testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug" );
	        instance.testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug", "" );
	        
	        instance.log4JLogger.debug(message="test message debug" );
			instance.log4JLogger.debug(message="test message debug", throwable="" );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testError" output="false" hint="Test of error method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        System.out.println("error");
	        instance.testLogger.error(Logger.SECURITY_SUCCESS, "test message error" );
	        instance.testLogger.error(Logger.SECURITY_SUCCESS, "test message error", "" );
	        
	        instance.log4JLogger.error(message="test message error" );
			instance.log4JLogger.error(message="test message error", throwable="" );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testWarning" output="false" hint="Test of warning method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        System.out.println("warning");
	        instance.testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning" );
	        instance.testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning", "" );
	        
	        instance.log4JLogger.warn(message="test message warning" );
			instance.log4JLogger.warn(message="test message warning", throwable="" );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testFatal" output="false" hint="Test of fatal method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        System.out.println("fatal");
	        instance.testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal" );
	        instance.testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal", "" );
	        
	        instance.log4JLogger.fatal(message="test message fatal" );
			instance.log4JLogger.fatal(message="test message fatal", throwable="" );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAlways" output="false" hint="Test of always method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        System.out.println("always");
	        instance.testLogger.always(Logger.SECURITY_SUCCESS, "test message always 1 (SECURITY_SUCCESS)" );
	        instance.testLogger.always(Logger.SECURITY_AUDIT, "test message always 2 (SECURITY_AUDIT)", "" );
	
		    instance.log4JLogger.always(message="test message always 3" );
			instance.log4JLogger.always(message="test message always 4", throwable="" );
	
	        try {
	        	throw new RuntimeException("What? You call that a 'throw'??? You couldn't hit the broad side of a barn (assuming that barns wore bras).");
	        } catch(RuntimeException rtex) {
	            instance.testLogger.always(Logger.SECURITY_AUDIT, "test message always 5", rtex );
	            instance.log4JLogger.always(message="test message always 6", throwable=rtex);
	        }
		</cfscript> 
	</cffunction>


</cfcomponent>

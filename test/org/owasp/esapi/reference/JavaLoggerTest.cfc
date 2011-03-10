<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.testCount = 0;
		instance.testLogger = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(session);
			structClear(request);

			Logger = javaLoader().create("org.owasp.esapi.Logger");

			instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");

			local.tmpConfig = createObject("component", "UnitTestSecurityConfiguration").init(instance.ESAPI, instance.ESAPI.securityConfiguration());
	        tmpConfig.setLogImplementation( getMetaData(createObject("component", "cfesapi.org.owasp.esapi.reference.JavaLogFactory")).name );
	        instance.ESAPI.override(local.tmpConfig);
	    	//This ensures a clean logger between tests
	    	instance.testLogger = instance.ESAPI.getLogger( "test" & instance.testCount++ );
	    	createObject("java", "java.lang.System").out.println("Test logger: " & instance.testLogger.toString());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			instance.testLogger = "";
			instance.ESAPI.override("");

			structClear(session);
			structClear(request);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testLogHTTPRequest" output="false" hint="Test of logHTTPRequest method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("logHTTPRequest");
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
	        createObject("java", "java.lang.System").out.println("setLevel");

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

	       	assertTrue(local.newLogger.isFatalEnabled());
	       	assertTrue(local.newLogger.isErrorEnabled());
	       	assertTrue(local.newLogger.isWarningEnabled());
	       	assertTrue(local.newLogger.isInfoEnabled());
	       	assertFalse(local.newLogger.isDebugEnabled());
	       	assertFalse(local.newLogger.isTraceEnabled());
	    </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testInfo" output="false" hint="Test of info method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("info");
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "test message" );
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "test message", "" );
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "%3escript%3f test message", "" );
	        instance.testLogger.info(Logger.SECURITY_SUCCESS, "<script> test message", "" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testTrace" output="false" hint="Test of trace method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("trace");
	        instance.testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace" );
	        instance.testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace", "" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testDebug" output="false" hint="Test of debug method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("debug");
	        instance.testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug" );
	        instance.testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug", "" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testError" output="false" hint="Test of error method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("error");
	        instance.testLogger.error(Logger.SECURITY_SUCCESS, "test message error" );
	        instance.testLogger.error(Logger.SECURITY_SUCCESS, "test message error", "" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testWarning" output="false" hint="Test of warning method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("warning");
	        instance.testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning" );
	        instance.testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning", "" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testFatal" output="false" hint="Test of fatal method, of class org.owasp.esapi.Logger.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("fatal");
	        instance.testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal" );
	        instance.testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal", "" );
    	</cfscript>
	</cffunction>


</cfcomponent>

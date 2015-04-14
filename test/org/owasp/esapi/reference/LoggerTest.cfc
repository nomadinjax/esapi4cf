/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.testCount = 0;
	variables.testLogger = "";

    public void function setUp() {
    	//This ensures a clean logger between tests
    	variables.testLogger = variables.ESAPI.getLogger( "test" & testCount++ );
    	variables.System.out.println("Test logger: " & variables.testLogger.toString());
    }

    public void function tearDown() {
    	//this helps, with garbage collection
    	structDelete(variables, "testLogger");
    }

    public void function testLogHTTPRequest() {
        variables.System.out.println("logHTTPRequest");
        var ignore = ["password","ssn","ccn"];
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
        variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
        var logger = variables.ESAPI.getLogger("logger");
        variables.ESAPI.httpUtilities().logHTTPRequest( httpRequest, logger, ignore );
        httpRequest.addParameter("one","one");
        httpRequest.addParameter("two","two1");
        httpRequest.addParameter("two","two2");
        httpRequest.addParameter("password","jwilliams");
        variables.ESAPI.httpUtilities().logHTTPRequest( httpRequest, logger, ignore );
    }


    /**
     * Test of setLevel method of the inner class org.owasp.esapi.reference.JavaLogger that is defined in
     * org.owasp.esapi.reference.JavaLogFactory.
     */
    public void function testSetLevel() {
        variables.System.out.println("setLevel");

        // The following tests that the default logging level is set to WARNING. Since the default might be changed
        // in the ESAPI security configuration file, these are commented out.
//       	assertTrue(variables.testLogger.isWarningEnabled());
//       	assertFalse(variables.testLogger.isInfoEnabled());

        // First, test all the different logging levels
        variables.testLogger.setLevel( variables.testLogger.LEVEL_ALL );
    	assertTrue(variables.testLogger.isFatalEnabled());
       	assertTrue(variables.testLogger.isErrorEnabled());
       	assertTrue(variables.testLogger.isWarningEnabled());
       	assertTrue(variables.testLogger.isInfoEnabled());
       	assertTrue(variables.testLogger.isDebugEnabled());
       	assertTrue(variables.testLogger.isTraceEnabled());

       	variables.testLogger.setLevel( variables.testLogger.LEVEL_TRACE );
    	assertTrue(variables.testLogger.isFatalEnabled());
       	assertTrue(variables.testLogger.isErrorEnabled());
       	assertTrue(variables.testLogger.isWarningEnabled());
       	assertTrue(variables.testLogger.isInfoEnabled());
       	assertTrue(variables.testLogger.isDebugEnabled());
       	assertTrue(variables.testLogger.isTraceEnabled());

       	variables.testLogger.setLevel( variables.testLogger.LEVEL_DEBUG );
    	assertTrue(variables.testLogger.isFatalEnabled());
       	assertTrue(variables.testLogger.isErrorEnabled());
       	assertTrue(variables.testLogger.isWarningEnabled());
       	assertTrue(variables.testLogger.isInfoEnabled());
       	assertTrue(variables.testLogger.isDebugEnabled());
       	assertFalse(variables.testLogger.isTraceEnabled());

       	variables.testLogger.setLevel( variables.testLogger.LEVEL_INFO );
    	assertTrue(variables.testLogger.isFatalEnabled());
       	assertTrue(variables.testLogger.isErrorEnabled());
       	assertTrue(variables.testLogger.isWarningEnabled());
       	assertTrue(variables.testLogger.isInfoEnabled());
       	assertFalse(variables.testLogger.isDebugEnabled());
       	assertFalse(variables.testLogger.isTraceEnabled());

       	variables.testLogger.setLevel( variables.testLogger.LEVEL_WARNING );
    	assertTrue(variables.testLogger.isFatalEnabled());
       	assertTrue(variables.testLogger.isErrorEnabled());
       	assertTrue(variables.testLogger.isWarningEnabled());
       	assertFalse(variables.testLogger.isInfoEnabled());
       	assertFalse(variables.testLogger.isDebugEnabled());
       	assertFalse(variables.testLogger.isTraceEnabled());

       	variables.testLogger.setLevel( variables.testLogger.LEVEL_ERROR );
    	assertTrue(variables.testLogger.isFatalEnabled());
       	assertTrue(variables.testLogger.isErrorEnabled());
       	assertFalse(variables.testLogger.isWarningEnabled());
       	assertFalse(variables.testLogger.isInfoEnabled());
       	assertFalse(variables.testLogger.isDebugEnabled());
       	assertFalse(variables.testLogger.isTraceEnabled());

       	variables.testLogger.setLevel( variables.testLogger.LEVEL_FATAL );
    	assertTrue(variables.testLogger.isFatalEnabled());
       	assertFalse(variables.testLogger.isErrorEnabled());
       	assertFalse(variables.testLogger.isWarningEnabled());
       	assertFalse(variables.testLogger.isInfoEnabled());
       	assertFalse(variables.testLogger.isDebugEnabled());
       	assertFalse(variables.testLogger.isTraceEnabled());

       	variables.testLogger.setLevel( variables.testLogger.LEVEL_OFF );
    	assertFalse(variables.testLogger.isFatalEnabled());
       	assertFalse(variables.testLogger.isErrorEnabled());
       	assertFalse(variables.testLogger.isWarningEnabled());
       	assertFalse(variables.testLogger.isInfoEnabled());
       	assertFalse(variables.testLogger.isDebugEnabled());
       	assertFalse(variables.testLogger.isTraceEnabled());

       	//Now test to see if a change to the logging level in one log affects other logs
       	var newLogger = variables.ESAPI.getLogger( "test_num2" );
       	variables.testLogger.setLevel( variables.testLogger.LEVEL_OFF );
       	newLogger.setLevel( variables.testLogger.LEVEL_INFO );
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
    }


    /**
	 * Test of info method, of class org.owasp.esapi.Logger.
	 */
    public void function testInfo() {
        variables.System.out.println("info");
        variables.testLogger.info(variables.testLogger.SECURITY_SUCCESS, "test message" );
        variables.testLogger.info(variables.testLogger.SECURITY_SUCCESS, "test message", javaCast("null", "") );
        variables.testLogger.info(variables.testLogger.SECURITY_SUCCESS, "%3escript%3f test message", javaCast("null", "") );
        variables.testLogger.info(variables.testLogger.SECURITY_SUCCESS, "<script> test message", javaCast("null", "") );
    }

    /**
	 * Test of trace method, of class org.owasp.esapi.Logger.
	 */
    public void function testTrace() {
        variables.System.out.println("trace");
        variables.testLogger.trace(variables.testLogger.SECURITY_SUCCESS, "test message trace" );
        variables.testLogger.trace(variables.testLogger.SECURITY_SUCCESS, "test message trace", javaCast("null", "") );
    }

    /**
	 * Test of debug method, of class org.owasp.esapi.Logger.
	 */
    public void function testDebug() {
        variables.System.out.println("debug");
        variables.testLogger.debug(variables.testLogger.SECURITY_SUCCESS, "test message debug" );
        variables.testLogger.debug(variables.testLogger.SECURITY_SUCCESS, "test message debug", javaCast("null", "") );
    }

    /**
	 * Test of error method, of class org.owasp.esapi.Logger.
	 */
    public void function testError() {
        variables.System.out.println("error");
        variables.testLogger.error(variables.testLogger.SECURITY_SUCCESS, "test message error" );
        variables.testLogger.error(variables.testLogger.SECURITY_SUCCESS, "test message error", javaCast("null", "") );
    }

    /**
	 * Test of warning method, of class org.owasp.esapi.Logger.
	 */
    public void function testWarning() {
        variables.System.out.println("warning");
        variables.testLogger.warning(variables.testLogger.SECURITY_SUCCESS, "test message warning" );
        variables.testLogger.warning(variables.testLogger.SECURITY_SUCCESS, "test message warning", javaCast("null", "") );
    }

    /**
	 * Test of fatal method, of class org.owasp.esapi.Logger.
	 */
    public void function testFatal() {
        variables.System.out.println("fatal");
        variables.testLogger.fatal(variables.testLogger.SECURITY_SUCCESS, "test message fatal" );
        variables.testLogger.fatal(variables.testLogger.SECURITY_SUCCESS, "test message fatal", javaCast("null", "") );
    }

    /**
     * Test of always method, of class org.owasp.esapi.Logger.
     */
    public void function testAlways() {

        variables.System.out.println("always");
        variables.testLogger.always(variables.testLogger.SECURITY_SUCCESS, "test message always 1 (SECURITY_SUCCESS)" );
        variables.testLogger.always(variables.testLogger.SECURITY_AUDIT,   "test message always 2 (SECURITY_AUDIT)" );
        variables.testLogger.always(variables.testLogger.SECURITY_SUCCESS, "test message always 3 (SECURITY_SUCCESS)", javaCast("null", "") );
        variables.testLogger.always(variables.testLogger.SECURITY_AUDIT,   "test message always 4 (SECURITY_AUDIT)", javaCast("null", "") );
        try {
        	raiseException(createObject("java", "java.lang.RuntimeException").init("What? You call that a 'throw'? My grandmother throws " &
        							   "better than that and she's been dead for more than 10 years!"));
        } catch(java.lang.RuntimeException rtex) {
            variables.testLogger.always(variables.testLogger.SECURITY_AUDIT,   "test message always 5", rtex );
        }
	}
}

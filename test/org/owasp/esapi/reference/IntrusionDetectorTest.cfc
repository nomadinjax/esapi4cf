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
import "org.owasp.esapi.errors.IntegrityException";
import "org.owasp.esapi.errors.IntrusionException";
import "org.owasp.esapi.errors.ValidationException";
import "org.owasp.esapi.util.RuntimeException";

component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	clearUserFile();

	/**
	 * Test of addException method, of class org.owasp.esapi.IntrusionDetector.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testAddException() {
		variables.System.out.println("addException");
		variables.ESAPI.intrusionDetector().addException( new RuntimeException("message") );
		variables.ESAPI.intrusionDetector().addException( new ValidationException(variables.ESAPI, "user message", "log message") );
		variables.ESAPI.intrusionDetector().addException( new IntrusionException(variables.ESAPI, "user message", "log message") );
		var username = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
        var auth = variables.ESAPI.authenticator();
		var user = auth.createUser(username, "addException", "addException");
		user.enable();
	    var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		user.loginWithPassword("addException");

		// Now generate some exceptions to disable account
		for ( var i = 0; i < variables.ESAPI.securityConfiguration().getQuota("org.owasp.esapi.errors.IntegrityException").count; i++ ) {
            // EnterpriseSecurityExceptions are added to IntrusionDetector automatically
            new IntegrityException( variables.ESAPI, "IntegrityException " & i, "IntegrityException " & i );
		}
        assertFalse( user.isLoggedIn() );
	}


    /**
     * Test of addEvent method, of class org.owasp.esapi.IntrusionDetector.
     *
     * @throws AuthenticationException
     *             the authentication exception
     */
    public void function testAddEvent() {
        variables.System.out.println("addEvent");
		var username = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
        var auth = variables.ESAPI.authenticator();
		var user = auth.createUser(username, "addEvent", "addEvent");
		user.enable();
	    var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		user.loginWithPassword("addEvent");

        // Now generate some events to disable user account
        for ( var i = 0; i < variables.ESAPI.securityConfiguration().getQuota("event.test").count; i++ ) {
            variables.ESAPI.intrusionDetector().addEvent("test", "test message");
        }
        assertFalse( user.isEnabled() );
    }

}

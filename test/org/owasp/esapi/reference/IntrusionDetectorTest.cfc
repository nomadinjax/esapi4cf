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
 * The Class IntrusionDetectorTest.
 */
component IntrusionDetectorTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();

	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
	 */
	
	public void function setUp() {
		structClear(request);
	}
	
	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
	 */
	
	public void function tearDown() {
		structClear(request);
	}
	
	/**
	 * Test of addException method, of class org.owasp.esapi.IntrusionDetector.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testAddException() {
		newJava("java.lang.System").out.println("addException");
		instance.ESAPI.intrusionDetector().addException(newJava("java.lang.RuntimeException").init("message"));
		local.exception = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "user message", "log message");
		instance.ESAPI.intrusionDetector().addException(local.exception);
		local.exception = new cfesapi.org.owasp.esapi.errors.IntrusionException(instance.ESAPI, "user message", "log message");
		instance.ESAPI.intrusionDetector().addException(local.exception);
		local.username = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
		local.auth = instance.ESAPI.authenticator();
		local.user = local.auth.createUser(local.username, "addException", "addException");
		local.user.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
		local.user.loginWithPassword(password="addException");
	
		// Now generate some exceptions to disable account
		for(local.i = 1; local.i <= instance.ESAPI.securityConfiguration().getQuota("cfesapi.org.owasp.esapi.errors.IntegrityException").count; local.i++) {
			// EnterpriseSecurityExceptions are added to IntrusionDetector automatically
			new cfesapi.org.owasp.esapi.errors.IntegrityException(instance.ESAPI, "IntegrityException " & i, "IntegrityException " & i);
		}
		assertFalse(local.user.isLoggedIn());
	}
	
	/**
	 * Test of addEvent method, of class org.owasp.esapi.IntrusionDetector.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testAddEvent() {
		newJava("java.lang.System").out.println("addEvent");
		local.username = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.auth = instance.ESAPI.authenticator();
		local.user = local.auth.createUser(local.username, "addEvent", "addEvent");
		local.user.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
		local.user.loginWithPassword(password="addEvent");
	
		// Now generate some events to disable user account
		for(local.i = 1; local.i <= instance.ESAPI.securityConfiguration().getQuota("event.test").count; local.i++) {
			instance.ESAPI.intrusionDetector().addEvent("test", "test message");
		}
		assertFalse(local.user.isEnabled());
	}
	
}
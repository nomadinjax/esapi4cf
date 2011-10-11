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
component extends="cfesapi.test.TestCase" {

	instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");

	public void function testFilter() {
		System = createObject("java", "java.lang.System");
	
		System.out.println("ClickjackFilter");
	
		local.mfc = {};
		local.filter = createObject("component", "cfesapi.org.owasp.esapi.filters.ClickjackFilter").init(instance.ESAPI, local.mfc);
		local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
	
		local.url = createObject("java", "java.net.URL").init("http://www.example.com/index.jsp");
		System.out.println("\nTest request: " & local.url);
		local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init(local.url);
		local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
		try {
			local.filter.doFilter(local.request, local.response);
			local.filter.destroy();
		}
		catch(java.lang.Exception e) {
			e.printStackTrace();
			fail();
		}
		local.header = local.response.getHeader("X-FRAME-OPTIONS");
		System.out.println(">>>" & local.header);
		assertEquals("DENY", local.header);
	}
	
}
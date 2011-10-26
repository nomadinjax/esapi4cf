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
 * The Class SafeRequestTest.
 */
component SafeRequestTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

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
	 *
	 */
	
	public void function testGetRequestParameters() {
		createObject("java", "java.lang.System").out.println("getRequestParameters");
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.request.addParameter("one", "1");
		local.request.addParameter("two", "2");
		local.request.addParameter("one", "3");
		local.request.addParameter("one", "4");
		local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
		local.params = local.safeRequest.getParameterValues("one");
		local.out = "";
		for(local.i = 1; local.i <= arrayLen(local.params); local.i++) {
			local.out &= local.params[local.i];
		}
		assertEquals("134", local.out);
	}
	
	public void function testGetQueryStringNull() {
		local.req = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.wrappedReq = "";
	
		local.req.setQueryString("");
		local.wrappedReq = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.req);
		assertIsEmpty(local.wrappedReq.getQueryString());
	}
	
	public void function testGetQueryStringNonNull() {
		local.req = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.wrappedReq = "";
	
		local.req.setQueryString("a=b");
		local.wrappedReq = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.req);
		assertEquals("a=b", local.wrappedReq.getQueryString());
	}
	
	public void function testGetQueryStringNUL() {
		local.req = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.wrappedReq = "";
	
		local.req.setQueryString("a=\u0000");
		local.wrappedReq = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.req);
		assertEquals("", local.wrappedReq.getQueryString());
	}
	
	public void function testGetQueryStringPercent() {
		local.req = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.wrappedReq = "";
	
		local.req.setQueryString("a=%62");
		local.wrappedReq = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.req);
		assertEquals("a=b", local.wrappedReq.getQueryString());
	}
	
	public void function testGetQueryStringPercentNUL() {
		local.req = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.wrappedReq = "";
	
		local.req.setQueryString("a=%00");
		local.wrappedReq = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.req);
		assertEquals("", local.wrappedReq.getQueryString());
	}
	
	/* these tests need to be enabled&changed based on the decisions
	 * made regarding issue 125. Currently they fail.
	public void function testGetQueryStringPercentEquals() {
	    local.req = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	    local.wrappedReq = "";
	
	    local.req.setQueryString("a=%3d");
	    local.wrappedReq = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.req);
	    assertEquals("a=%3d",local.wrappedReq.getQueryString());
	}
	
	public void function testGetQueryStringPercentAmpersand() {
	    local.req = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	    local.wrappedReq = "";
	
	    local.req.setQueryString("a=%26b");
	    local.wrappedReq = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.req);
	    assertEquals("a=%26b",local.wrappedReq.getQueryString());
	}
	*/
	// Test to ensure null-value contract defined by ServletRequest.getParameterNames(String) is met.
	
	public void function testGetParameterValuesReturnsNullWhenParameterDoesNotExistInRequest() {
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.request.clearParameters();
	
		local.paramName = "nonExistentParameter";
		assertIsEmptyArray(local.request.getParameterValues(local.paramName));
	
		local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
		assertIsEmptyArray(local.safeRequest.getParameterValues(local.paramName), "Expecting null value to be returned for non-existent parameter.");
	}
	
	public void function testGetParameterValuesReturnsCorrectValueWhenParameterExistsInRequest() {
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.request.clearParameters();
	
		local.paramName = "existentParameter";
		local.paramValue = "foobar";
		local.request.addParameter(local.paramName, local.paramValue);
		assertTrue(local.request.getParameterValues(local.paramName)[1] == local.paramValue);
	
		local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
		local.actualParamValue = local.safeRequest.getParameterValues(local.paramName)[1];
		assertEquals(local.paramValue, local.actualParamValue);
	}
	
	public void function testGetParameterValuesReturnsCorrectValuesWhenParameterExistsMultipleTimesInRequest() {
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.request.clearParameters();
	
		local.paramName = "existentParameter";
		local.paramValue_0 = "foobar";
		local.paramValue_1 = "barfoo";
		local.request.addParameter(local.paramName, local.paramValue_0);
		local.request.addParameter(local.paramName, local.paramValue_1);
		assertTrue(local.request.getParameterValues(local.paramName)[1] == local.paramValue_0);
		assertTrue(local.request.getParameterValues(local.paramName)[2] == local.paramValue_1);
	
		local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
		local.actualParamValues = local.safeRequest.getParameterValues(local.paramName);
		assertEquals(local.paramValue_0, local.actualParamValues[1]);
		assertEquals(local.paramValue_1, local.actualParamValues[2]);
	}
	
}
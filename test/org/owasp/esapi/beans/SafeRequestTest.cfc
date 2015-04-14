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
import "org.owasp.esapi.beans.SafeRequest";
import "org.owasp.esapi.util.Utils";

/**
 * The Class SafeRequestTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	public void function testGetRequestParameters() {
		variables.System.out.println( "getRequestParameters");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.addParameter( "one","1" );
		httpRequest.addParameter( "two","2" );
		httpRequest.addParameter( "one","3" );
		httpRequest.addParameter( "one","4" );
		safeRequest = new SafeRequest( variables.ESAPI, httpRequest );
		var params = safeRequest.getParameterValues("one");
		var out = "";
		for (var i = 1; i <= arrayLen(params); i++ ) out &= params[i];
		assertEquals( "134", out );
	}

	public void function testGetQueryStringNull()
	{
		var req = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();

		req.setQueryString(javaCast("null", ""));
		var wrappedReq = new SafeRequest( variables.ESAPI, req );
		assertEquals("", wrappedReq.getQueryString());
	}

	public void function testGetQueryStringNonNull()
	{
		var req = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();

		req.setQueryString("a=b");
		var wrappedReq = new SafeRequest(variables.ESAPI, req);
		assertEquals("a=b",wrappedReq.getQueryString());
	}

	public void function testGetQueryStringNUL()
	{
		var req = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();

		req.setQueryString("a=" & new Utils().toUnicode("\u0000"));
		var wrappedReq = new SafeRequest(variables.ESAPI, req);
		assertEquals("a=",wrappedReq.getQueryString());
	}

	public void function testGetQueryStringPercent()
	{
		var req = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();

		req.setQueryString("a=%62");
		var wrappedReq = new SafeRequest(variables.ESAPI, req);
		assertEquals("a=b",wrappedReq.getQueryString());
	}

	public void function testGetQueryStringPercentNUL()
	{
		var req = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();

		req.setQueryString("a=%00");
		var wrappedReq = new SafeRequest(variables.ESAPI, req);
		assertEquals("",wrappedReq.getQueryString());
	}

	/* these tests need to be enabled&changed based on the decisions
	 * made regarding issue 125. Currently they fail.
	public void function testGetQueryStringPercentEquals()
	{
		var req = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();

		req.setQueryString("a=%3d");
		var wrappedReq = new SafeRequest(variables.ESAPI, req);
		assertEquals("a=%3d",wrappedReq.getQueryString());
	}

	public void function testGetQueryStringPercentAmpersand()
	{
		var req = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();

		req.setQueryString("a=%26b");
		var wrappedReq = new SafeRequest(variables.ESAPI, req);
		assertEquals("a=%26b",wrappedReq.getQueryString());
	}
	*/

	// Test to ensure null-value contract defined by ServletRequest.getParameterNames(String) is met.
	public void function testGetParameterValuesReturnsNullWhenParameterDoesNotExistInRequest() {
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.clearParameters();

		var paramName = "nonExistentParameter";
		assertTrue(isNull(httpRequest.getParameterValues(paramName)));

		var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
		assertEquals(0, arrayLen(safeRequest.getParameterValues(paramName)), "Expecting null value to be returned for non-existent parameter.");
	}

	public void function testGetParameterValuesReturnsCorrectValueWhenParameterExistsInRequest() {
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.clearParameters();

		var paramName = "existentParameter";
		var paramValue = "foobar";
		httpRequest.addParameter(paramName, paramValue);
		assertTrue(httpRequest.getParameterValues(paramName)[1] == paramValue);

		var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
		var actualParamValue = safeRequest.getParameterValues(paramName)[1];
		assertEquals(paramValue, actualParamValue);
	}

	public void function testGetParameterValuesReturnsCorrectValuesWhenParameterExistsMultipleTimesInRequest() {
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.clearParameters();

		var paramName = "existentParameter";
		var paramValue_0 = "foobar";
		var paramValue_1 = "barfoo";
		httpRequest.addParameter(paramName, paramValue_0);
		httpRequest.addParameter(paramName, paramValue_1);
		assertTrue(httpRequest.getParameterValues(paramName)[1] == paramValue_0);
		assertTrue(httpRequest.getParameterValues(paramName)[2] == paramValue_1);

		var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
		var actualParamValues = safeRequest.getParameterValues(paramName);
		assertEquals(paramValue_0, actualParamValues[1]);
		assertEquals(paramValue_1, actualParamValues[2]);
	}
}

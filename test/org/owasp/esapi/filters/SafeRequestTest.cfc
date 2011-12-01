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
<cfcomponent displayname="SafeRequestTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false" hint="The Class SafeRequestTest.">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear(request);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			structClear(request);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetRequestParameters" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("getRequestParameters");
			local.request = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.request.addParameter("one", "1");
			local.request.addParameter("two", "2");
			local.request.addParameter("one", "3");
			local.request.addParameter("one", "4");
			local.safeRequest = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.request);
			local.params = local.safeRequest.getParameterValues("one");
			local.out = "";
			for(local.i = 1; local.i <= arrayLen(local.params); local.i++) {
				local.out &= local.params[local.i];
			}
			assertEquals("134", local.out);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetQueryStringNull" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.req = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.wrappedReq = "";

			local.req.setQueryString("");
			local.wrappedReq = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.req);
			assertIsEmpty(local.wrappedReq.getQueryString());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetQueryStringNonNull" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.req = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.wrappedReq = "";

			local.req.setQueryString("a=b");
			local.wrappedReq = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.req);
			assertEquals("a=b", local.wrappedReq.getQueryString());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetQueryStringNUL" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.req = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.wrappedReq = "";

			local.req.setQueryString("a=\u0000");
			local.wrappedReq = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.req);
			assertEquals("", local.wrappedReq.getQueryString());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetQueryStringPercent" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.req = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.wrappedReq = "";

			local.req.setQueryString("a=%62");
			local.wrappedReq = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.req);
			assertEquals("a=b", local.wrappedReq.getQueryString());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetQueryStringPercentNUL" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.req = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.wrappedReq = "";

			local.req.setQueryString("a=%00");
			local.wrappedReq = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.req);
			assertEquals("", local.wrappedReq.getQueryString());
		</cfscript>

	</cffunction>

	<!--- these tests need to be enabled&changed based on the decisions made regarding issue 125. Currently they fail.
	<cffunction access="public" returntype="void" name="testGetQueryStringPercentEquals" output="false">
	    <cfset var local = {}/>
	    <cfscript>
	        local.req = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
	        local.wrappedReq = "";

	        local.req.setQueryString("a=%3d");
	        local.wrappedReq = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.req);
	        assertEquals("a=%3d", local.wrappedReq.getQueryString());
	    </cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetQueryStringPercentAmpersand" output="false">
	    <cfset var local = {}/>
	    <cfscript>
	        local.req = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
	        local.wrappedReq = "";

	        local.req.setQueryString("a=%26b");
	        local.wrappedReq = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.req);
	        assertEquals("a=%26b", local.wrappedReq.getQueryString());
	    </cfscript>

	</cffunction> --->

	<cffunction access="public" returntype="void" name="testGetParameterValuesReturnsNullWhenParameterDoesNotExistInRequest" output="false"
	            hint="Test to ensure null-value contract defined by ServletRequest.getParameterNames(String) is met.">
		<cfset var local = {}/>

		<cfscript>
			local.request = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.request.clearParameters();

			local.paramName = "nonExistentParameter";
			assertIsEmptyArray(local.request.getParameterValues(local.paramName));

			local.safeRequest = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.request);
			assertIsEmptyArray(local.safeRequest.getParameterValues(local.paramName), "Expecting null value to be returned for non-existent parameter.");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetParameterValuesReturnsCorrectValueWhenParameterExistsInRequest" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.request = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.request.clearParameters();

			local.paramName = "existentParameter";
			local.paramValue = "foobar";
			local.request.addParameter(local.paramName, local.paramValue);
			local.result = local.request.getParameterValues(local.paramName);
			assertTrue(local.result[1] == local.paramValue);

			local.safeRequest = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.request);
			local.safeResult = local.safeRequest.getParameterValues(local.paramName);
			local.actualParamValue = local.safeResult[1];
			assertEquals(local.paramValue, local.actualParamValue);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetParameterValuesReturnsCorrectValuesWhenParameterExistsMultipleTimesInRequest" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.request = newComponent("cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.request.clearParameters();

			local.paramName = "existentParameter";
			local.paramValue_0 = "foobar";
			local.paramValue_1 = "barfoo";
			local.request.addParameter(local.paramName, local.paramValue_0);
			local.request.addParameter(local.paramName, local.paramValue_1);
			local.result = local.request.getParameterValues(local.paramName);
			assertTrue(local.result[1] == local.paramValue_0);
			assertTrue(local.result[2] == local.paramValue_1);

			local.safeRequest = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.request);
			local.actualParamValues = local.safeRequest.getParameterValues(local.paramName);
			assertEquals(local.paramValue_0, local.actualParamValues[1]);
			assertEquals(local.paramValue_1, local.actualParamValues[2]);
		</cfscript>

	</cffunction>

</cfcomponent>
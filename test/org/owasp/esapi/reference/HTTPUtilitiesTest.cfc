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
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();
		clearUserFile();

		instance.CLASS = getMetaData( this );
		instance.CLASS_NAME = listLast( instance.CLASS.name, "." );
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear( request );
			structClear( session );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testAddCSRFToken" output="false"
	            hint="Test of addCSRFToken method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			local.authenticator = instance.ESAPI.authenticator();
			local.username = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.user = local.authenticator.createUser( local.username, "addCSRFToken", "addCSRFToken" );
			local.authenticator.setCurrentUser( local.user );

			System.out.println( "addCSRFToken" );
			local.csrf1 = instance.ESAPI.httpUtilities().addCSRFToken( "/test1" );
			System.out.println( "CSRF1:" & local.csrf1 );
			assertTrue( local.csrf1.indexOf( "?" ) > -1 );

			local.csrf2 = instance.ESAPI.httpUtilities().addCSRFToken( "/test1?one=two" );
			System.out.println( "CSRF2:" & local.csrf2 );
			assertTrue( local.csrf2.indexOf( "&" ) > -1 );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testChangeSessionIdentifier" output="false"
	            hint="Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			System.out.println( "changeSessionIdentifier" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			local.session = local.request.getSession();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.session.setAttribute( "one", "one" );
			local.session.setAttribute( "two", "two" );
			local.session.setAttribute( "three", "three" );
			local.id1 = local.session.getId();
			local.session = instance.ESAPI.httpUtilities().changeSessionIdentifier( instance.ESAPI.currentRequest() );
			local.id2 = local.session.getId();
			assertTrue( !local.id1.equals( local.id2 ) );
			assertEquals( "one", local.session.getAttribute( "one" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetFileUploads" output="false"
	            hint="Test of formatHttpRequestForLog method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			System.out.println( "getFileUploads" );
			local.dir = "";

			local.dir = createObject( "component", "cfesapi.test.org.owasp.esapi.util.FileTestUtils" ).createTmpDirectory( prefix=instance.CLASS_NAME );
			local.content = '--ridiculous\r\nContent-Disposition: form-data; name="upload"; filename="testupload.txt"\r\nContent-Type: application/octet-stream\r\n\r\nThis is a test of the multipart broadcast system.\r\nThis is only a test.\r\nStop.\r\n\r\n--ridiculous\r\nContent-Disposition: form-data; name="submit"\r\n\r\nSubmit Query\r\n--ridiculous--\r\nEpilogue';

			local.request1 = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init( "/test", local.content.getBytes() );
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request1, local.response );
			try {
				instance.ESAPI.httpUtilities().getSafeFileUploads( instance.ESAPI.currentRequest(), local.dir, local.dir );
				fail();
			}
			catch(cfesapi.org.owsap.esapi.errors.ValidationException e) {
				// expected
			}

			local.request2 = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init( "/test", local.content.getBytes() );
			local.request2.setContentType( "multipart/form-data; boundary=ridiculous" );
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request2, local.response );
			try {
				local.list = instance.ESAPI.httpUtilities().getSafeFileUploads( instance.ESAPI.currentRequest(), local.dir, local.dir );
				local.i = list.iterator();
				while(local.i.hasNext()) {
					local.f = local.i.next();
					System.out.println( "  " & local.f.getAbsolutePath() );
				}
				assertTrue( local.list.size() > 0 );
			}
			catch(cfesapi.org.owsap.esapi.errors.ValidationException e) {
				fail();
			}

			local.request3 = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init( "/test", local.content.replaceAll( "txt", "ridiculous" ).getBytes() );
			local.request3.setContentType( "multipart/form-data; boundary=ridiculous" );
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request3, local.response );
			try {
				instance.ESAPI.httpUtilities().getSafeFileUploads( instance.ESAPI.currentRequest(), local.dir, local.dir );
				fail();
			}
			catch(cfesapi.org.owsap.esapi.errors.ValidationException e) {
				// expected
			}
			createObject( "component", "cfesapi.test.org.owasp.esapi.util.FileTestUtils" ).deleteRecursively( local.dir );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidHTTPRequest" output="false"
	            hint="Test of isValidHTTPRequest method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			System.out.println( "isValidHTTPRequest" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.request.addParameter( "p1", "v1" );
			local.request.addParameter( "p2", "v3" );
			local.request.addParameter( "p3", "v2" );
			local.request.addHeader( "h1", "v1" );
			local.request.addHeader( "h2", "v1" );
			local.request.addHeader( "h3", "v1" );
			local.list = [];
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "c1", "v1" ) );
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "c2", "v2" ) );
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "c3", "v3" ) );
			local.request.setCookies( local.list );
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init() );

			// should throw IntrusionException which will be caught in isValidHTTPRequest and return false
			local.request.setMethod( "JEFF" );
			//assertFalse( instance.ESAPI.validator().isValidHTTPRequest() );

			local.request.setMethod( "POST" );
			//assertTrue( instance.ESAPI.validator().isValidHTTPRequest() );
			local.request.setMethod( "GET" );
			//assertTrue( instance.ESAPI.validator().isValidHTTPRequest() );
			local.request.addParameter( "bad_name", "bad##value" );
			local.request.addHeader( "bad_name", "bad##value" );
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "bad_name", "bad##value" ) );

			// call the validator directly, since the safe request will shield this from failing
			assertFalse( instance.ESAPI.validator().isValidHTTPRequest( local.request ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testKillAllCookies" output="false"
	            hint="Test of killAllCookies method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			System.out.println( "killAllCookies" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.safeResponse = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeResponse" ).init( instance.ESAPI, local.response );
			assertTrue( local.response.getCookies().isEmpty() );
			local.list = [];
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "test1", "1" ) );
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "test2", "2" ) );
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "test3", "3" ) );
			local.request.setCookies( local.list );
			instance.ESAPI.httpUtilities().killAllCookies( instance.ESAPI.currentRequest(), local.safeResponse );
			// this tests getHeaders because we're using addHeader in our setCookie method
			assertTrue( local.response.getHeaderNames().size() == 3 );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testKillCookie" output="false"
	            hint="Test of killCookie method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			System.out.println( "killCookie" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			local.safeResponse = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeResponse" ).init( instance.ESAPI, local.response );
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			assertTrue( local.response.getCookies().isEmpty() );
			local.list = [];
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "test1", "1" ) );
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "test2", "2" ) );
			local.list.add( getJava( "javax.servlet.http.Cookie" ).init( "test3", "3" ) );
			local.request.setCookies( local.list );
			instance.ESAPI.httpUtilities().killCookie( instance.ESAPI.currentRequest(), local.safeResponse, "test1" );
			// this tests getHeaders because we're using addHeader in our setCookie method
			assertTrue( local.response.getHeaderNames().size() == 1 );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSendSafeRedirect" output="false"
	            hint="Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			System.out.println( "sendSafeRedirect" );
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			local.safeResponse = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeResponse" ).init( instance.ESAPI, local.response );
			try {
				local.safeResponse.sendRedirect( "/test1/abcdefg" );
				local.safeResponse.sendRedirect( "/test2/1234567" );
			}
			catch(java.io.IOException e) {
				fail("");
			}
			try {
				local.safeResponse.sendRedirect( "http://www.aspectsecurity.com" );
				fail("");
			}
			catch(java.io.IOException e) {
				// expected
			}
			try {
				local.safeResponse.sendRedirect( "/ridiculous" );
				fail("");
			}
			catch(java.io.IOException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetCookie" output="false"
	            hint="Test of setCookie method, of class org.owasp.esapi.HTTPUtilities.">

		<cfscript>
			var local = {};

			System.out.println( "setCookie" );
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			local.safeResponse = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeResponse" ).init( instance.ESAPI, local.response );
			assertTrue( local.response.getCookies().isEmpty() );

			local.safeResponse.addCookie( getJava( "javax.servlet.http.Cookie" ).init( "test1", "test1" ) );
			assertTrue( local.response.getHeaderNames().size() == 1 );

			local.safeResponse.addCookie( getJava( "javax.servlet.http.Cookie" ).init( "test2", "test2" ) );
			assertTrue( local.response.getHeaderNames().size() == 2 );

			// test illegal name
			local.safeResponse.addCookie( getJava( "javax.servlet.http.Cookie" ).init( "tes<t3", "test3" ) );
			assertTrue( local.response.getHeaderNames().size() == 2 );

			// test illegal value
			local.safeResponse.addCookie( getJava( "javax.servlet.http.Cookie" ).init( "test3", "tes<t3" ) );
			assertTrue( local.response.getHeaderNames().size() == 2 );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetStateFromEncryptedCookie" output="false"
	            hint="">

		<cfscript>
			var local = {};

			System.out.println( "getStateFromEncryptedCookie" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.safeResponse = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeResponse" ).init( instance.ESAPI, local.response );
			local.map = {};
			local.map.put( "one", "aspect" );
			local.map.put( "two", "ridiculous" );
			local.map.put( "test_hard", "&(@##*!^|;,." );
			try {
				instance.ESAPI.httpUtilities().encryptStateInCookie( local.safeResponse, local.map );
				local.value = local.response.getHeader( "Set-Cookie" );
				local.encrypted = local.value.substring( local.value.indexOf( "=" ) + 1, local.value.indexOf( ";" ) );
				local.request.setCookie( "state", local.encrypted );
				local.state = instance.ESAPI.httpUtilities().decryptStateFromCookie( instance.ESAPI.currentRequest() );
				local.i = local.map.entrySet().iterator();
				while(local.i.hasNext()) {
					local.entry = local.i.next();
					local.origname = local.entry.getKey();
					local.origvalue = local.entry.getValue();
					local.test = "";
					if (structKeyExists(local.state, local.origname)) {
						local.test = local.state.get( local.origname );
					}
					if(local.test != local.origvalue) {
						fail("");
					}
				}
			}
			catch(cfesapi.org.owsap.esapi.errors.EncryptionException e) {
				fail("");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSaveStateInEncryptedCookie" output="false"
	            hint="">

		<cfscript>
			var local = {};

			System.out.println( "saveStateInEncryptedCookie" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			local.safeResponse = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeResponse" ).init( instance.ESAPI, local.response );
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.map = {};
			local.map.put( "one", "aspect" );
			local.map.put( "two", "ridiculous" );
			local.map.put( "test_hard", "&(@##*!^|;,." );
			try {
				instance.ESAPI.httpUtilities().encryptStateInCookie( local.safeResponse, local.map );
				local.value = local.response.getHeader( "Set-Cookie" );
				local.encrypted = local.value.substring( local.value.indexOf( "=" ) + 1, local.value.indexOf( ";" ) );
				instance.ESAPI.encryptor().decryptString( local.encrypted );
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				fail();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetNoCacheHeaders" output="false"
	            hint="Test set no cache headers.">

		<cfscript>
			var local = {};

			System.out.println( "setNoCacheHeaders" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			assertTrue( local.response.getHeaderNames().isEmpty() );
			local.response.addHeader( "test1", "1" );
			local.response.addHeader( "test2", "2" );
			local.response.addHeader( "test3", "3" );
			assertFalse( local.response.getHeaderNames().isEmpty() );
			instance.ESAPI.httpUtilities().setNoCacheHeaders( instance.ESAPI.currentResponse() );
			assertTrue( local.response.containsHeader( "Cache-Control" ) );
			assertTrue( local.response.containsHeader( "Expires" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetRememberToken" output="false">

		<cfscript>
			var local = {};

			System.out.println( "setRememberToken" );
			local.authenticator = instance.ESAPI.authenticator();
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.password = local.authenticator.generateStrongPassword();
			local.user = local.authenticator.createUser( local.accountName, local.password, local.password );
			local.user.enable();
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.request.addParameter( "username", local.accountName );
			local.request.addParameter( "password", local.password );
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );

			local.maxAge = (60 * 60 * 24 * 14);
			instance.ESAPI.httpUtilities().setRememberToken( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), local.password, local.maxAge, "domain", "/" );
			// Can't test this because we're using safeSetCookie, which sets a header, not a real cookie!
			// String value = response.getCookie( Authenticator.REMEMBER_TOKEN_COOKIE_NAME ).getValue();
			// assertEquals( user.getRememberToken(), value );
		</cfscript>

	</cffunction>

</cfcomponent>
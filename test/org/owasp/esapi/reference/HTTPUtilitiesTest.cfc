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
import "org.owasp.esapi.beans.SafeResponse";
import "org.owasp.esapi.crypto.CipherText";

/**
 * The Class HTTPUtilitiesTest.
 */
component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	clearUserFile();

	variables.CLASS = getMetaData(this);
	variables.CLASS_NAME = variables.CLASS.name;

	public void function testCSRFToken() {
		variables.System.out.println( "CSRFToken");
		var username = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var user = variables.ESAPI.authenticator().createUser(username, "addCSRFToken", "addCSRFToken");
		variables.ESAPI.authenticator().setCurrentUser( user );
		var token = variables.ESAPI.httpUtilities().getCSRFToken();
		assertEquals( 8, token.length() );
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		try {
			variables.ESAPI.httpUtilities().verifyCSRFToken(httpRequest);
			fail("");
		} catch( any e ) {
			// expected
		}
		httpRequest.addParameter( variables.ESAPI.httpUtilities().CSRF_TOKEN_NAME, token );
		variables.ESAPI.httpUtilities().verifyCSRFToken(httpRequest);
	}

	/**
	 * Test of addCSRFToken method, of class org.owasp.esapi.HTTPUtilities.
	 * @throws AuthenticationException
	 */
	public void function testAddCSRFToken() {
		var instance = variables.ESAPI.authenticator();
		var username = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var user = instance.createUser(username, "addCSRFToken", "addCSRFToken");
		instance.setCurrentUser( user );

		variables.System.out.println("addCSRFToken");
		var csrf1 = variables.ESAPI.httpUtilities().addCSRFToken("/test1");
		variables.System.out.println( "CSRF1:" & csrf1);
		assertTrue(csrf1.indexOf("?") > -1);

		var csrf2 = variables.ESAPI.httpUtilities().addCSRFToken("/test1?one=two");
		variables.System.out.println( "CSRF1:" & csrf1);
		assertTrue(csrf2.indexOf("&") > -1);
	}


	/**
	 * Test of assertSecureRequest method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void function testAssertSecureRequest() {
		variables.System.out.println("assertSecureRequest");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		try {
			httpRequest.setRequestURL( "http://example.com");
			variables.ESAPI.httpUtilities().assertSecureRequest( httpRequest );
			fail("");
		} catch( org.owasp.esapi.errors.AccessControlException e ) {
			// pass
		}
		try {
			httpRequest.setRequestURL( "ftp://example.com");
			variables.ESAPI.httpUtilities().assertSecureRequest( httpRequest );
			fail("");
		} catch( org.owasp.esapi.errors.AccessControlException e ) {
			// pass
		}
		try {
			httpRequest.setRequestURL("");
			variables.ESAPI.httpUtilities().assertSecureRequest( httpRequest );
			fail("");
		} catch( any e ) {
			// pass
		}
		try {
			httpRequest.setRequestURL( javaCast("null", "") );
			variables.ESAPI.httpUtilities().assertSecureRequest( httpRequest );
			fail("");
		} catch( any e ) {
			// pass
		}
		try {
			httpRequest.setRequestURL( "https://example.com");
			variables.ESAPI.httpUtilities().assertSecureRequest( httpRequest );
			// pass
		} catch( org.owasp.esapi.errors.AccessControlException e ) {
			fail("");
		}
	}


	/**
	 * Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
	 *
	 * @throws EnterpriseSecurityException
	 */
	public void function testChangeSessionIdentifier() {
		variables.System.out.println("changeSessionIdentifier");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		var httpSession = httpRequest.getSession();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		httpSession.setAttribute("one", "one");
		httpSession.setAttribute("two", "two");
		httpSession.setAttribute("three", "three");
		var id1 = httpSession.getId();
		httpSession = variables.ESAPI.httpUtilities().changeSessionIdentifier( httpRequest );
		var id2 = httpSession.getId();
		assertTrue(id1 != id2);
		assertEquals("one", httpSession.getAttribute("one"));
	}

	/**
	 * Test of formatHttpRequestForLog method, of class org.owasp.esapi.HTTPUtilities.
	 * @throws IOException
	 */
	public void function testGetFileUploads() {
		var home = "";

		//try {
			home = getTempDirectory();
			var content = '--ridiculous\r\nContent-Disposition: form-data; name="upload"; filename="testupload.txt"\r\nContent-Type: application/octet-stream\r\n\r\nThis is a test of the multipart broadcast variables.System.\r\nThis is only a test.\r\nStop.\r\n\r\n--ridiculous\r\nContent-Disposition: form-data; name="submit"\r\n\r\nSubmit Query\r\n--ridiculous--\r\nEpilogue';

			var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
			var httpRequest1 = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init("/test", content.getBytes(httpResponse.getCharacterEncoding()));
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest1, httpResponse);
			try {
				variables.ESAPI.httpUtilities().getFileUploads(uploadDir=home, httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest());
				fail("");
			} catch( org.owasp.esapi.errors.ValidationException e ) {
				// expected
			}

			var httpRequest2 = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init("/test", content.getBytes(httpResponse.getCharacterEncoding()));
			httpRequest2.setContentType( "multipart/form-data; boundary=ridiculous");
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest2, httpResponse);
			try {
				var list = variables.ESAPI.httpUtilities().getFileUploads(uploadDir=home, httpRequest=httpRequest2);
				var i = list.iterator();
				while ( i.hasNext() ) {
					var f = i.next();
					variables.System.out.println( "  " & f.getAbsolutePath() );
				}
				assertTrue( list.size() > 0 );
			} catch (org.owasp.esapi.errors.ValidationException e) {
				fail("");
			}

			var httpRequest4 = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init("/test", content.getBytes(httpResponse.getCharacterEncoding()));
			httpRequest4.setContentType( "multipart/form-data; boundary=ridiculous");
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest4, httpResponse);
			variables.System.err.println("UPLOAD DIRECTORY: " & variables.ESAPI.securityConfiguration().getUploadDirectory());
			try {
				var list = variables.ESAPI.httpUtilities().getFileUploads(uploadDir=home, httpRequest=httpRequest4);
				var i = list.iterator();
				while ( i.hasNext() ) {
					var f = i.next();
					variables.System.out.println( "  " & f.getAbsolutePath() );
				}
				assertTrue( list.size() > 0 );
			} catch (org.owasp.esapi.errors.ValidationException e) {
				variables.System.err.println("ERROR: " & e.toString());
				fail("");
			}

			var httpRequest3 = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init("/test", content.replaceAll("txt", "ridiculous").getBytes(httpResponse.getCharacterEncoding()));
			httpRequest3.setContentType( "multipart/form-data; boundary=ridiculous");
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest3, httpResponse);
			try {
				variables.ESAPI.httpUtilities().getFileUploads(uploadDir=home, httpRequest=httpRequest3);
				fail("");
			} catch (org.owasp.esapi.errors.ValidationException e) {
				// expected
			}
		/*}
		finally {
			FileTestUtils.deleteRecursively(home);
		}*/

	}



	/**
	 * Test of killAllCookies method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void function testKillAllCookies() {
		variables.System.out.println("killAllCookies");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		assertTrue(httpResponse.getCookies().isEmpty());
		var list = createObject("java", "java.util.ArrayList").init();
		list.add(createObject("java", "javax.servlet.http.Cookie").init("test1", "1"));
		list.add(createObject("java", "javax.servlet.http.Cookie").init("test2", "2"));
		list.add(createObject("java", "javax.servlet.http.Cookie").init("test3", "3"));
		httpRequest.setCookies(list);
		variables.ESAPI.httpUtilities().killAllCookies(httpRequest, httpResponse);
		assertEquals(3, arrayLen(httpRequest.getCookies()));
	}

	/**
	 * Test of killCookie method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void function testKillCookie() {
		variables.System.out.println("killCookie");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		assertTrue(httpResponse.getCookies().isEmpty());
		var list = createObject("java", "java.util.ArrayList").init();
		list.add(createObject("java", "javax.servlet.http.Cookie").init("test1", "1"));
		list.add(createObject("java", "javax.servlet.http.Cookie").init("test2", "2"));
		list.add(createObject("java", "javax.servlet.http.Cookie").init("test3", "3"));
		httpRequest.setCookies(list);
		variables.ESAPI.httpUtilities().killCookie("test1", httpRequest, httpResponse);
		assertEquals(1, httpResponse.getCookies().size());
	}

	/**
	 * Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
	 *
	 * @throws ValidationException the validation exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public void function testSendSafeRedirect() {
		variables.System.out.println("sendSafeRedirect");
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		try {
			variables.ESAPI.httpUtilities().sendRedirect("/test1/abcdefg", httpResponse);
			variables.ESAPI.httpUtilities().sendRedirect("/test2/1234567", httpResponse);
		} catch (java.io.IOException e) {
			fail("");
		}
		try {
			variables.ESAPI.httpUtilities().sendRedirect("http://www.aspectsecurity.com", httpResponse);
			fail("");
		} catch (java.io.IOException e) {
			// expected
		}
		try {
			variables.ESAPI.httpUtilities().sendRedirect("/ridiculous", httpResponse);
			fail("");
		} catch (java.io.IOException e) {
			// expected
		}
	}

	/**
	 * Test of setCookie method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void function testSetCookie() {
		variables.System.out.println("setCookie");
		var instance = variables.ESAPI.httpUtilities();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		assertTrue(httpResponse.getHeaderNames().isEmpty());

		instance.addCookie( createObject("java", "javax.servlet.http.Cookie").init( "test1", "test1" ), httpResponse );
		assertTrue(httpResponse.getHeaderNames().size() == 1);

		instance.addCookie( createObject("java", "javax.servlet.http.Cookie").init( "test2", "test2" ), httpResponse );
		assertTrue(httpResponse.getHeaderNames().size() == 2);

		// test illegal name
		instance.addCookie( createObject("java", "javax.servlet.http.Cookie").init( "tes<t3", "test3" ), httpResponse );
		assertTrue(httpResponse.getHeaderNames().size() == 2);

		// test illegal value
		instance.addCookie( createObject("java", "javax.servlet.http.Cookie").init( "test3", "tes<t3" ), httpResponse );
		assertTrue(httpResponse.getHeaderNames().size() == 2);
	}

	/**
	 *
	 * @throws java.lang.Exception
	 */
	public void function testGetStateFromEncryptedCookie() {
		variables.System.out.println("getStateFromEncryptedCookie");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();

		// test null cookie array
		var empty = variables.ESAPI.httpUtilities().decryptStateFromCookie(httpRequest);
		assertTrue( empty.isEmpty() );

		var map = {};
		map.put( "one", "aspect" );
		map.put( "two", "ridiculous" );
		map.put( "test_hard", "&(@##*!^|;,." );
		try {
			variables.ESAPI.httpUtilities().encryptStateInCookie(map, httpResponse);
			var value = httpResponse.getHeader( "Set-Cookie" );
			var encrypted = value.substring(value.indexOf("=")+1, value.indexOf(";"));
			httpRequest.setCookie( variables.ESAPI.httpUtilities().ESAPI_STATE, encrypted );
			var state = variables.ESAPI.httpUtilities().decryptStateFromCookie(httpRequest);
			var i = map.entrySet().iterator();
			while ( i.hasNext() ) {
				var entry = i.next();
				var origname = entry.getKey();
				var origvalue = entry.getValue();
				if( state.get( origname ) != origvalue ) {
					fail();
				}
			}
		} catch( org.owasp.esapi.errors.EncryptionException e ) {
			fail("");
		}
	}

	/**
	 *
	 */
	public void function testSaveStateInEncryptedCookie() {
		variables.System.out.println("saveStateInEncryptedCookie");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		var map = {};
		map.put( "one", "aspect" );
		map.put( "two", "ridiculous" );
		map.put( "test_hard", "&(@##*!^|;,." );
		try {
			variables.ESAPI.httpUtilities().encryptStateInCookie(map, httpResponse);
			var value = httpResponse.getHeader( "Set-Cookie" );
			var encrypted = value.substring(value.indexOf("=")+1, value.indexOf(";"));
			var serializedCiphertext = createObject("java", "org.owasp.esapi.codecs.Hex").decode(encrypted);
	        var restoredCipherText = new CipherText(variables.ESAPI).fromPortableSerializedBytes(serializedCiphertext);
	        variables.ESAPI.encryptor().decrypt(restoredCipherText);
		} catch( org.owasp.esapi.errors.EncryptionException e ) {
			fail("");
		}
	}


	/**
	 *
	 */
	public void function testSaveTooLongStateInEncryptedCookieException() {
		variables.System.out.println("saveTooLongStateInEncryptedCookie");

		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);

		var foo = variables.ESAPI.randomizer().getRandomString(4096, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);

		var map = {};
		map.put("long", foo);
		try {
			variables.ESAPI.httpUtilities().encryptStateInCookie(map, httpResponse);
			fail("Should have thrown an exception");
		}
		catch (org.owasp.esapi.errors.EncryptionException expected) {
			//expected
		}
	}

	/**
	 * Test set no cache headers.
	 */
	public void function testSetNoCacheHeaders() {
		variables.System.out.println("setNoCacheHeaders");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		assertTrue(httpResponse.getHeaderNames().isEmpty());
		httpResponse.addHeader("test1", "1");
		httpResponse.addHeader("test2", "2");
		httpResponse.addHeader("test3", "3");
		assertFalse(httpResponse.getHeaderNames().isEmpty());
		variables.ESAPI.httpUtilities().setNoCacheHeaders( httpResponse );
		assertTrue(httpResponse.containsHeader("Cache-Control"));
		assertTrue(httpResponse.containsHeader("Expires"));
	}

	/**
	 *
	 * @throws org.owasp.esapi.errors.AuthenticationException
	 */
	public void function testSetRememberToken() {
		variables.System.out.println("setRememberToken");
		var instance = variables.ESAPI.authenticator();
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var password = instance.generateStrongPassword();
		var user = instance.createUser(accountName, password, password);
		user.enable();
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.addParameter("username", accountName);
		httpRequest.addParameter("password", password);
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		instance.login( httpRequest, httpResponse);

		var maxAge = ( 60 * 60 * 24 * 14 );
		variables.ESAPI.httpUtilities().setRememberToken( password, maxAge, "domain", "/", httpRequest, httpResponse );
		// Can't test this because we're using safeSetCookie, which sets a header, not a real cookie!
		// String value = httpResponse.getCookie( Authenticator.REMEMBER_TOKEN_COOKIE_NAME ).getValue();
		// assertEquals( user.getRememberToken(), value );
	}

	public void function testGetSessionAttribute() {
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpSession = httpRequest.getSession();
		var value = createObject("java", "java.lang.Float").init("43f");
		httpSession.setAttribute("testAttribute", value);

		/* NO ERROR: don't understand the difference between the 1st and 2nd call
		try {
			var test1 = variables.ESAPI.httpUtilities().getSessionAttribute( "testAttribute", httpSession );
			fail("");
		} catch ( java.lang.ClassCastException cce ) {}*/

		var test2 = variables.ESAPI.httpUtilities().getSessionAttribute( "testAttribute", httpSession );
		assertEquals( test2, value );
	}

	public void function testGetRequestAttribute() {
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var value = createObject("java", "java.lang.Float").init("43f");
		httpRequest.setAttribute( "testAttribute", value );

		/* NO ERROR: don't understand the difference between the 1st and 2nd call
		try {
			var test1 = variables.ESAPI.httpUtilities().getRequestAttribute( "testAttribute", httpRequest );
			fail("");
		} catch ( java.lang.ClassCastException cce ) {}*/

		var test2 = variables.ESAPI.httpUtilities().getRequestAttribute( "testAttribute", httpRequest );
		assertEquals( test2, value );
	}

	public void function testEncryptQueryString() {
		var encryptedValue = variables.ESAPI.httpUtilities().encryptQueryString("test1=value1&test2=value2");
		assertEquals({"test1": "value1", "test2": "value2"}, variables.ESAPI.httpUtilities().decryptQueryString(encryptedValue));

		var encryptedValue = variables.ESAPI.httpUtilities().encryptQueryString("redirect=" & variables.ESAPI.encoder().encodeForURL("http://mydomain.com/samplepage.html?test1=value1&test2=value2"));
		assertEquals({"redirect": "http://mydomain.com/samplepage.html?test1=value1&test2=value2"}, variables.ESAPI.httpUtilities().decryptQueryString(encryptedValue));
	}

}

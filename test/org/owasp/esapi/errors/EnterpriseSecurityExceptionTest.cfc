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
component EnterpriseSecurityExceptionTest extends="cfesapi.test.TestCase" {

	// imports
	System = createObject("java", "java.lang.System");
	Throwable = createObject("java", "java.lang.Throwable");

	/**
	 * {@inheritDoc}
	 * @throws Exception
	 */
	
	public void function setUp() {
		instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
	}
	
	/**
	 * {@inheritDoc}
	 * @throws Exception
	 */
	
	public void function tearDown() {
		instance.ESAPI = "";
	}
	
	/**
	 * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
	 * 
	 */
	
	public void function testExceptions() {
		System.out.println("exceptions");
		//local.e = null;    // null not valid in CF
		local.e = new cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException(instance.ESAPI, "m1", "m2", Throwable.init());
		assertEquals(local.e.getUserMessage(), "m1");
		assertEquals(local.e.getLogMessage(), "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AccessControlException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.AccessControlException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AccessControlException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.AvailabilityException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.AvailabilityException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AvailabilityException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.CertificateException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.CertificateException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.CertificateException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.EncodingException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.EncodingException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.EncodingException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.EncryptionException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.EncryptionException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.EncryptionException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.ExecutorException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.ExecutorException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.ExecutorException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage="m1", logMessage="m2", context="context");
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "m1", "m2", Throwable.init(), "context");
	
		local.e = new cfesapi.org.owasp.esapi.errors.IntegrityException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.IntegrityException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.IntegrityException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationHostException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationHostException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationHostException(instance.ESAPI, "m1", "m2", Throwable.init());
	
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException(instance.ESAPI, "m1", "m2", Throwable.init());
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationUploadException(instance.ESAPI);
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationUploadException(instance.ESAPI, "m1", "m2");
		local.e = new cfesapi.org.owasp.esapi.errors.ValidationUploadException(instance.ESAPI, "m1", "m2", Throwable.init());
	
		local.ve = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI);
		local.ve.setContext("test");
		assertEquals("test", local.ve.getContext());
	
		local.ex = new cfesapi.org.owasp.esapi.errors.IntrusionException(instance.ESAPI, "test", "test details");
		local.ex = new cfesapi.org.owasp.esapi.errors.IntrusionException(instance.ESAPI, "m1", "m2");
		local.ex = new cfesapi.org.owasp.esapi.errors.IntrusionException(instance.ESAPI, "m1", "m2", Throwable.init());
		assertEquals(local.ex.getUserMessage(), "m1");
		assertEquals(local.ex.getLogMessage(), "m2");
	}
	
}
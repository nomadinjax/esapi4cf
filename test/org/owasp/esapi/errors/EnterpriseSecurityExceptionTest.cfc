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
import "org.owasp.esapi.errors.AccessControlException";
import "org.owasp.esapi.errors.AuthenticationAccountsException";
import "org.owasp.esapi.errors.AuthenticationCredentialsException";
import "org.owasp.esapi.errors.AuthenticationException";
import "org.owasp.esapi.errors.AuthenticationHostException";
import "org.owasp.esapi.errors.AuthenticationLoginException";
import "org.owasp.esapi.errors.AvailabilityException";
import "org.owasp.esapi.errors.CertificateException";
import "org.owasp.esapi.errors.EncodingException";
import "org.owasp.esapi.errors.EncryptionException";
import "org.owasp.esapi.errors.EnterpriseSecurityException";
import "org.owasp.esapi.errors.ExecutorException";
import "org.owasp.esapi.errors.IntegrityException";
import "org.owasp.esapi.errors.IntrusionException";
import "org.owasp.esapi.errors.ValidationAvailabilityException";
import "org.owasp.esapi.errors.ValidationException";
import "org.owasp.esapi.errors.ValidationUploadException";

/**
 * The Class EnterpriseSecurityExceptionTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

    /**
	 * Test of update method, of class org.owasp.esapi.EnterpriseSecurityException.
	 *
	 */
    public void function testExceptions() {
        variables.System.out.println("exceptions");

        var e = "";
        e = new EnterpriseSecurityException(variables.ESAPI, "m1","m2");
        e = new EnterpriseSecurityException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        assertEquals( e.getUserMessage(), "m1" );
        assertEquals( e.getLogMessage(), "m2" );
        e = new AccessControlException(variables.ESAPI, "m1","m2");
        e = new AccessControlException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new AuthenticationException(variables.ESAPI, "m1","m2");
        e = new AuthenticationException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new AvailabilityException(variables.ESAPI, "m1","m2");
        e = new AvailabilityException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new CertificateException(variables.ESAPI, "m1","m2");
        e = new CertificateException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new EncodingException(variables.ESAPI, "m1","m2");
        e = new EncodingException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new EncryptionException(variables.ESAPI, "m1","m2");
        e = new EncryptionException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new ExecutorException(variables.ESAPI, "m1","m2");
        e = new ExecutorException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new ValidationException(variables.ESAPI, "m1","m2");
        e = new ValidationException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new ValidationException(variables.ESAPI, "m1","m2","context");
        e = new ValidationException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init(),"context");

        e = new IntegrityException(variables.ESAPI, "m1","m2");
        e = new IntegrityException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new AuthenticationHostException(variables.ESAPI, "m1","m2");
        e = new AuthenticationHostException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());

        e = new AuthenticationAccountsException(variables.ESAPI, "m1","m2");
        e = new AuthenticationAccountsException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new AuthenticationCredentialsException(variables.ESAPI, "m1","m2");
        e = new AuthenticationCredentialsException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new AuthenticationLoginException(variables.ESAPI, "m1","m2");
        e = new AuthenticationLoginException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new ValidationAvailabilityException(variables.ESAPI, "m1","m2");
        e = new ValidationAvailabilityException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());
        e = new ValidationUploadException(variables.ESAPI, "m1","m2");
        e = new ValidationUploadException(variables.ESAPI, "m1","m2",createObject("java", "java.lang.Throwable").init());

        var ve = new ValidationException(variables.ESAPI, "m1","m2");
        ve.setContext("test");
        assertEquals( "test", ve.getContext() );

        var ex = new IntrusionException( variables.ESAPI, "test", "test details");
        ex = new IntrusionException(variables.ESAPI, "m1","m2");
        ex = new IntrusionException(variables.ESAPI, "m1","m2", createObject("java", "java.lang.Throwable").init());
        assertEquals( ex.getUserMessage(), "m1" );
        assertEquals( ex.getLogMessage(), "m2" );
    }

}

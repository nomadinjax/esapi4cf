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
	</cfscript>

    <cffunction access="public" returtype="void" name="testExceptions" output="false">
		<cfscript>
			var local = {};

	        System.out.println("exceptions");
	        local.e = "";
	        //.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        assertEquals( local.e.getUserMessage(), "m1" );
	        assertEquals( local.e.getLogMessage(), "m2" );
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AvailabilityException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AvailabilityException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AvailabilityException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.CertificateException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.CertificateException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.CertificateException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.IntegrityException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.IntegrityException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.IntegrityException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationHostException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationHostException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationHostException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());

	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());
	        //local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI);
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI,"m1","m2");
	        local.e = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI,"m1","m2",getJava("java.lang.Throwable").init());

	        local.ex = createObject("component", "cfesapi.org.owasp.esapi.errors.IntrusionException").init(instance.ESAPI, "test", "test details");
	        local.ex = createObject("component", "cfesapi.org.owasp.esapi.errors.IntrusionException").init(instance.ESAPI,"m1","m2");
	        local.ex = createObject("component", "cfesapi.org.owasp.esapi.errors.IntrusionException").init(instance.ESAPI,"m1","m2", getJava("java.lang.Throwable").init());
	        assertEquals( local.ex.getUserMessage(), "m1" );
	        assertEquals( local.ex.getLogMessage(), "m2" );
	    </cfscript>
	</cffunction>

</cfcomponent>
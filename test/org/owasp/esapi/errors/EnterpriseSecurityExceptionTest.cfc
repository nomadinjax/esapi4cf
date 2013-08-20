<!---
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
--->
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		variables.ESAPI = createObject( "component", "org.owasp.esapi.ESAPI" ).init();
	</cfscript>
 
	<cffunction access="public" returtype="void" name="testExceptions" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var ex = "";
			
	        System.out.println("exceptions");
	        ex = "";
	        //ex = createObject("component", "org.owasp.esapi.errors.EnterpriseSecurityException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.EnterpriseSecurityException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.EnterpriseSecurityException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        assertEquals( ex.getUserMessage(), "m1" );
	        assertEquals( ex.getLogMessage(), "m2" );
	        //ex = createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.AvailabilityException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.AvailabilityException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.AvailabilityException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.CertificateException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.CertificateException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.CertificateException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.EncodingException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.EncodingException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.EncodingException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.EncryptionException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.EncryptionException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.EncryptionException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.IntegrityException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.IntegrityException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.IntegrityException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.AuthenticationHostException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationHostException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationHostException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());

	        //ex = createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());
	        //ex = createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI);
	        ex = createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI,"m1","m2",newJava("java.lang.Throwable").init());

	        ex = createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, "test", "test details");
	        ex = createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI,"m1","m2");
	        ex = createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI,"m1","m2", newJava("java.lang.Throwable").init());
	        assertEquals( ex.getUserMessage(), "m1" );
	        assertEquals( ex.getLogMessage(), "m2" );
	    </cfscript> 
	</cffunction>


</cfcomponent>

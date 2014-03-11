<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="esapi4cf.test.unit.org.owasp.esapi.util.TestCase" output="false">

	<cffunction access="public" returtype="void" name="testExceptions" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var ex = "";
			var t = createObject("java", "java.lang.Throwable");

			System.out.println("exceptions");
			ex = "";
			//ex = createObject("component", "org.owasp.esapi.errors.EnterpriseSecurityException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.EnterpriseSecurityException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.EnterpriseSecurityException").init(request.ESAPI, "m1", "m2", t.init());
			assertEquals(ex.getUserMessage(), "m1");
			assertEquals(ex.getLogMessage(), "m2");
			//ex = createObject("component", "org.owasp.esapi.errors.AccessControlException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.AccessControlException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.AccessControlException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.AvailabilityException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.AvailabilityException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.AvailabilityException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.CertificateException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.CertificateException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.CertificateException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.EncodingException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.EncodingException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.EncodingException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.EncryptionException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.EncryptionException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.EncryptionException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.ExecutorException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.ExecutorException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.ExecutorException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.ValidationException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.ValidationException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.ValidationException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.IntegrityException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.IntegrityException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.IntegrityException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.AuthenticationHostException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationHostException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationHostException").init(request.ESAPI, "m1", "m2", t.init());

			//ex = createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(request.ESAPI, "m1", "m2", t.init());
			//ex = createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(request.ESAPI);
			ex = createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(request.ESAPI, "m1", "m2", t.init());

			ex = createObject("component", "org.owasp.esapi.errors.IntrusionException").init(request.ESAPI, "test", "test details");
			ex = createObject("component", "org.owasp.esapi.errors.IntrusionException").init(request.ESAPI, "m1", "m2");
			ex = createObject("component", "org.owasp.esapi.errors.IntrusionException").init(request.ESAPI, "m1", "m2", t.init());
			assertEquals(ex.getUserMessage(), "m1");
			assertEquals(ex.getLogMessage(), "m2");
		</cfscript>

	</cffunction>

</cfcomponent>
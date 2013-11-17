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

	<cffunction access="public" returntype="void" name="testSetters" output="false"
	            hint="Test of all the ESAPI setter methods">

		<cfscript>
			System.out.println("testSetters");
			request.ESAPI.setAccessController(request.ESAPI.accessController());
			request.ESAPI.setAuthenticator(request.ESAPI.authenticator());
			request.ESAPI.setEncoder(request.ESAPI.encoder());
			request.ESAPI.setEncryptor(request.ESAPI.encryptor());
			request.ESAPI.setExecutor(request.ESAPI.executor());
			request.ESAPI.setHttpUtilities(request.ESAPI.httpUtilities());
			request.ESAPI.setIntrusionDetector(request.ESAPI.intrusionDetector());
			request.ESAPI.setRandomizer(request.ESAPI.randomizer());
			request.ESAPI.setSecurityConfiguration(request.ESAPI.securityConfiguration());
			request.ESAPI.setValidator(request.ESAPI.validator());
		</cfscript>

	</cffunction>

</cfcomponent>
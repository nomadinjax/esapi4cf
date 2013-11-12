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
			variables.ESAPI.setAccessController(variables.ESAPI.accessController());
			variables.ESAPI.setAuthenticator(variables.ESAPI.authenticator());
			variables.ESAPI.setEncoder(variables.ESAPI.encoder());
			variables.ESAPI.setEncryptor(variables.ESAPI.encryptor());
			variables.ESAPI.setExecutor(variables.ESAPI.executor());
			variables.ESAPI.setHttpUtilities(variables.ESAPI.httpUtilities());
			variables.ESAPI.setIntrusionDetector(variables.ESAPI.intrusionDetector());
			variables.ESAPI.setRandomizer(variables.ESAPI.randomizer());
			variables.ESAPI.setSecurityConfiguration(variables.ESAPI.securityConfiguration());
			variables.ESAPI.setValidator(variables.ESAPI.validator());
		</cfscript>

	</cffunction>

</cfcomponent>
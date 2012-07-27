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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 --->
<!---
 * The Class ESAPITest.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
--->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		System = createObject( "java", "java.lang.System" );
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();
	</cfscript>

	<cffunction access="public" returntype="void" name="testSetters" output="false"
	            hint="Test of all the ESAPI setter methods">

		<cfscript>
			System.out.println( "testSetters" );
			instance.ESAPI.setAccessController( instance.ESAPI.accessController() );
			instance.ESAPI.setAuthenticator( instance.ESAPI.authenticator() );
			instance.ESAPI.setEncoder( instance.ESAPI.encoder() );
			instance.ESAPI.setEncryptor( instance.ESAPI.encryptor() );
			instance.ESAPI.setExecutor( instance.ESAPI.executor() );
			instance.ESAPI.setHttpUtilities( instance.ESAPI.httpUtilities() );
			instance.ESAPI.setIntrusionDetector( instance.ESAPI.intrusionDetector() );
			instance.ESAPI.setRandomizer( instance.ESAPI.randomizer() );
			instance.ESAPI.setSecurityConfiguration( instance.ESAPI.securityConfiguration() );
			instance.ESAPI.setValidator( instance.ESAPI.validator() );
		</cfscript>

	</cffunction>


</cfcomponent>
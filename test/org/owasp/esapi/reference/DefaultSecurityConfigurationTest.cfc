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
		variables.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();
		variables.CLASS = getMetaData(this);
		variables.conf = "";
	</cfscript>
	
	<cffunction access="public" returntype="void" name="setUp" output="false">
		
		<cfscript>
			variables.conf = createObject("component", "org.owasp.esapi.reference.DefaultSecurityConfiguration").init(variables.ESAPI);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="tearDown" output="false">
		
		<cfscript>
			variables.conf = "";
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="testGetResourceStreamMissing" output="false"
	            hint="Verify that a FileNotFoundException is thrown for a missing resource and not a NPE.">
		
		<cfscript>
			try {
				variables.conf.getResourceStream("file.that.should.not.exist");
				fail('getResourceStream("file.that.should.not.exist" did not throw a FileNotFoundException');
			}
			catch(java.io.FileNotFoundException expected) {
				// success
			}
		</cfscript>
		
	</cffunction>
	
</cfcomponent>
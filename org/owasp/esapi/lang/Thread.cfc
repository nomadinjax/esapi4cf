<!--- /**
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
 */ --->
<cfcomponent displayname="Thread" extends="cfesapi.org.owasp.esapi.lang.Object" output="false">

	<cfscript>
		instance.thread = newJava("java.lang.Thread").init();
	</cfscript>

	<cffunction access="public" returntype="void" name="start" output="false">

		<cfscript>
			instance.thread.start();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="join" output="false">

		<cfscript>
			instance.thread.join();
		</cfscript>

	</cffunction>

</cfcomponent>
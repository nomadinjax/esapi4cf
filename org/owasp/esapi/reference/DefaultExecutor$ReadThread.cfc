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
<cfcomponent displayname="ReadThread" extends="cfesapi.org.owasp.esapi.lang.Thread" output="false">
	
	<cfscript>
		this.exception = "";
		instance.stream = "";
		instance.buffer = "";
	</cfscript>
	
	<cffunction access="public" returntype="DefaultExecutor$ReadThread" name="init" output="false">
		<cfargument required="true" name="stream"/>
		<cfargument required="true" name="buffer"/>
	
		<cfscript>
			instance.stream = arguments.stream;
			instance.buffer = arguments.buffer;
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="run" output="false">
		
		<cfscript>
			try {
				readStream(instance.stream, instance.buffer);
			}
			catch(java.io.IOException e) {
				this.exception = e;
			}
		</cfscript>
		
	</cffunction>
	
</cfcomponent>
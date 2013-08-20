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
<cfcomponent extends="org.owasp.esapi.util.Object" output="false">

	<cfscript>
		variables.ESAPI = "";

		this.key = "";
		this.times = [];
	</cfscript>
 
	<cffunction access="public" returntype="DefaultIntrusionDetector$Event" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI">
		<cfargument required="true" type="String" name="key">
		<cfscript>
			variables.ESAPI = arguments.ESAPI;

			this.key = arguments.key;

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="increment" output="false">
		<cfargument required="true" type="numeric" name="count">
		<cfargument required="true" type="numeric" name="interval">
		<cfscript>
			// CF8 requires 'var' at the top
			var timestamp = "";
			var past = "";
			var plong = "";
			var nlong = "";
			
			if(variables.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			timestamp = newJava( "java.util.Date" ).init();
			arrayPrepend(this.times, timestamp);
			while(arrayLen(this.times) > arguments.count) {
				arrayDeleteAt(this.times, arrayLen(this.times));
			}
			if(arrayLen(this.times) == arguments.count) {
				past = this.times[arguments.count];
				plong = past.getTime();
				nlong = timestamp.getTime();
				if(nlong - plong < arguments.interval * 1000) {
					throwException( createObject( "component", "org.owasp.esapi.errors.IntrusionException" ).init( variables.ESAPI, "Threshold exceeded", "Exceeded threshold for " & this.key ) );
				}
			}
		</cfscript> 
	</cffunction>


</cfcomponent>

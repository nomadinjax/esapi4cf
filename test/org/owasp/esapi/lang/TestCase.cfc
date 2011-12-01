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
<cfcomponent displayname="TestCase" extends="mxunit.framework.TestCase" output="false" hint="All CFESAPI test cases extend this component. If your MXUnit path is different, you can change it here to affect all tests. If you need anything applied to all test cases, put them here">

	<cfscript>
		instance.javaCache = {};
	</cfscript>

	<cffunction access="private" returntype="binary" name="newByte" output="false"
	            hint="Return an empty byte array with specified length">
		<cfargument required="true" type="numeric" name="len"/>

		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.sb.setLength(arguments.len);
			return local.sb.toStringESAPI().getBytes();
		</cfscript>

	</cffunction>

	<cffunction access="private" name="newJava" output="false" hint="Returns a reference to the specified Java class. Internally, this stores the reference for reuse to save on the number of classes created per request.">
		<cfargument required="true" name="classpath"/>

		<cfscript>
			if(!structKeyExists(instance.javaCache, arguments.classpath)) {
				instance.javaCache[arguments.classpath] = createObject("java", arguments.classpath);
			}
			return instance.javaCache[arguments.classpath];
		</cfscript>

	</cffunction>

	<cffunction access="private" name="newComponent" output="false" hint="Returns a reference to the specified component.">
		<cfargument required="true" name="classpath"/>

		<cfscript>
			return createObject("component", arguments.classpath);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="cleanUpUsers" output="false"
	            hint="Deletes the users.txt file from the User's Home directory. This prevents the file from getting too large and causing the test cases to take an extremely long time to run.">
		<cfset var local = {}/>

		<cfscript>
			local.filePath = newJava("java.lang.System").getProperty("user.home") & "/esapi/users.txt";
			if(fileExists(local.filePath)) {
				try {
					fileDelete(local.filePath);
				}
				catch(Any e) {
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="writeDump" output="true">
		<cfargument required="true" name="var"/>
		<cfargument type="boolean" name="abort" default="false"/>

		<cfdump var="#arguments.var#">
		<cfif arguments.abort>
			<cfabort>
		</cfif>
	</cffunction>

	<!--- <cfif listFirst(server.coldFusion.productVersion) LTE 8> --->

	<cffunction access="private" returntype="numeric" name="arrayFind" output="false">
		<cfargument required="true" type="Array" name="array"/>
		<cfargument required="true" name="object"/>

		<cfset var local = {}/>

		<cfscript>
			if(isSimpleValue(arguments.object)) {
				for(local.i = 1; local.i <= arrayLen(arguments.array); local.i++) {
					if(arguments.object == arguments.array[local.i]) {
						return local.i;
					}
				}
			}
			else {
				for(local.i = 1; local.i <= arrayLen(arguments.array); local.i++) {
					if(arguments.object.equals(arguments.array[local.i])) {
						return local.i;
					}
				}
			}
			return 0;
		</cfscript>

	</cffunction>

	<!--- </cfif> --->
</cfcomponent>
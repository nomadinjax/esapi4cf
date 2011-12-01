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
<cfcomponent displayname="Object" output="false">

	<cffunction access="public" returntype="Object" name="init" output="false"
	            hint="Generic init.">

		<cfscript>
			return this;
		</cfscript>

	</cffunction>

	<!--- private methods --->

	<cffunction access="private" returntype="void" name="assert" output="false">
		<cfargument required="true" type="boolean" name="boolean_expression"/>
		<cfargument type="String" name="string_expression"/>

		<cfif not arguments.boolean_expression>
			<cfthrow object="#newJava('java.lang.AssertionError').init(arguments.string_expression)#"/>
		</cfif>
	</cffunction>

	<cffunction access="private" returntype="binary" name="newByte" outuput="false">
		<cfargument type="numeric" name="len" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.sb.setLength(arguments.len);
			return local.sb.toStringESAPI().getBytes();
		</cfscript>

	</cffunction>

	<cfscript>
		instance.javaCache = {};
	</cfscript>

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

	<cffunction access="private" returntype="void" name="throwError" output="false">
		<cfargument required="true" name="exception"/>

		<!--- // CFESAPI RuntimeExceptions --->
		<cfif isInstanceOf(arguments.exception, "cfesapi.org.owasp.esapi.lang.RuntimeException")>
			<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
			<!--- // CFESAPI Exceptions --->
		<cfelseif isInstanceOf(arguments.exception, "cfesapi.org.owasp.esapi.lang.Exception")>
			<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getUserMessage()#" detail="#arguments.exception.getLogMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
			<!--- // Java Exceptions --->
		<cfelseif isInstanceOf(arguments.exception, "java.lang.Throwable")>
			<cfthrow object="#arguments.exception#"/>
		<cfelseif isStruct(arguments.exception)>
			<cfthrow attributecollection="#arguments.exception#"/>
		</cfif>
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
					if(arguments.object.equalsESAPI(arguments.array[local.i])) {
						return local.i;
					}
				}
			}
			return 0;
		</cfscript>

	</cffunction>

	<!--- </cfif> --->
</cfcomponent>
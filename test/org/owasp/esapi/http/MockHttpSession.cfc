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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.HttpSession" output="false">

	<cfscript>
		/* The invalidated. */
		instance.invalidated = false;

		/* The creation time. */
		instance.creationTime = newJava("java.util.Date").getTime();

		/* The accessed time. */
		instance.accessedTime = newJava("java.util.Date").getTime();

		/* The count. */
		if (!structKeyExists(request, "count")) {
			request.count = 1;
		}

		/* The sessionid. */
		instance.sessionid = request.count++;

		/* The attributes. */
		instance.attributes = {};
	</cfscript>
 
	<cffunction access="public" returntype="MockHttpSession" name="init" output="false" hint="Instantiates a new test http session.">
		<cfargument type="numeric" name="creationTime" required="false" hint="the creation time">
		<cfargument type="numeric" name="accessedTime" required="false" hint="the accessed time">
		<cfscript>
			if (structKeyExists(arguments, "creationTime")) {
				instance.creationTime = arguments.creationTime;
			}
			if (structKeyExists(arguments, "accessedTime")) {
				instance.accessedTime = arguments.accessedTime;
			}

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getAttribute" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			if (structKeyExists(instance.attributes, arguments.name)) {
				return instance.attributes.get( arguments.name );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false" hint="java.util.Enumeration">
		<cfscript>
			return listToArray(structKeyList(instance.attributes));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false">
		<cfscript>
			return instance.creationTime;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getId" output="false">
		<cfscript>
			return ""&instance.sessionid;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getInvalidated" output="false" hint="Gets the invalidated.">
		<cfscript>
			return instance.invalidated;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLastAccessedTime" output="false">
		<cfscript>
			return instance.accessedTime;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxInactiveInterval" output="false">
		<cfscript>
			return 0;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getServletContext" output="false">
		<cfscript>
			return "";
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="invalidate" output="false">
		<cfscript>
			instance.invalidated = true;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isNew" output="false">
		<cfscript>
			return true;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="removeAttribute" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			instance.attributes.remove( arguments.name );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="any" name="value" required="true">
		<cfscript>
			instance.attributes.put(arguments.name, arguments.value);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setMaxInactiveInterval" output="false">
		<cfargument type="numeric" name="interval" required="true">
		<cfscript>
			// stub
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setAccessedTime" output="false">
		<cfargument type="numeric" name="time" required="true">
		<cfscript>
			instance.accessedTime = arguments.time;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setCreationTime" output="false">
		<cfargument type="numeric" name="time" required="true">
		<cfscript>
			instance.creationTime = arguments.time;
		</cfscript> 
	</cffunction>


</cfcomponent>

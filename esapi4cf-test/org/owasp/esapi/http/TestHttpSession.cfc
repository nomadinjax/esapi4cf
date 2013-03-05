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
 * @author Damon Miller
 * @created 2011
 --->
<!--- implements="esapi4cf.org.owasp.esapi.HttpSession" --->
<cfcomponent extends="esapi4cf.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		/** The invalidated. */
		instance.invalidated = false;

		/** The creation time. */
		instance.creationTime = getJava( "java.util.Date" ).getTime();

		/** The accessed time. */
		instance.accessedTime = getJava( "java.util.Date" ).getTime();

		/** The count. */
		if(!structKeyExists(request, "count")) {
			request.count = 1;
		}

		/** The sessionid. */
		instance.sessionid = request.count++;

		/** The attributes. */
		instance.attributes = {};
	</cfscript>

	<cffunction access="public" returntype="TestHttpSession" name="init" output="false"
	            hint="Instantiates a new test http session.">
		<cfargument type="Date" name="creationTime" hint="the creation time"/>
		<cfargument type="Date" name="accessedTime" hint="the accessed time"/>

		<cfscript>
			if(structKeyExists( arguments, "creationTime" )) {
				instance.creationTime = arguments.creationTime;
			}
			if(structKeyExists( arguments, "accessedTime" )) {
				instance.accessedTime = arguments.accessedTime;
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			if(structKeyExists( instance.attributes, arguments.name )) {
				return instance.attributes.get( arguments.name );
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false">

		<cfscript>
			return listToArray( structKeyList( instance.attributes ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false">

		<cfscript>
			return instance.creationTime;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getId" output="false">

		<cfscript>
			return "" & instance.sessionid;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getInvalidated" output="false"
	            hint="Gets the invalidated.">

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

	<cffunction access="public" name="getServletContext" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getSessionContext" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValue" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getValueNames" output="false">

		<cfscript>
			var local = {};
			local.ret = [];
			return local.ret;
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

	<cffunction access="public" returntype="void" name="putValue" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="value"/>

		<cfscript>
			// stub
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			// stub
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeValue" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			// stub
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="value"/>

		<cfscript>
			instance.attributes.put( arguments.name, arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setMaxInactiveInterval" output="false">
		<cfargument required="true" type="numeric" name="interval"/>

		<cfscript>
			// stub
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccessedTime" output="false">
		<cfargument required="true" type="numeric" name="time"/>

		<cfscript>
			instance.accessedTime = arguments.time;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCreationTime" output="false">
		<cfargument required="true" type="numeric" name="time"/>

		<cfscript>
			instance.creationTime = arguments.time;
		</cfscript>

	</cffunction>

</cfcomponent>
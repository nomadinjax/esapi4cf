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
<!--- implements="org.owasp.esapi.util.HttpSession" --->
<cfcomponent extends="org.owasp.esapi.util.Object" output="false">

	<cfscript>
		/** The invalidated. */
		variables.invalidated = false;
	
		/** The creation time. */
		variables.creationTime = newJava("java.util.Date").getTime();
	
		/** The accessed time. */
		variables.accessedTime = newJava("java.util.Date").getTime();
	
		/** The count. */
		if(!structKeyExists(request, "count")) {
			request.count = 1;
		}
	
		/** The sessionid. */
		variables.sessionid = request.count++;
	
		/** The attributes. */
		variables.attributes = {};
	</cfscript>
	
	<cffunction access="public" returntype="TestHttpSession" name="init" output="false"
	            hint="Instantiates a new test http session.">
		<cfargument type="Date" name="creationTime" hint="the creation time"/>
		<cfargument type="Date" name="accessedTime" hint="the accessed time"/>
	
		<cfscript>
			if(structKeyExists(arguments, "creationTime")) {
				variables.creationTime = arguments.creationTime;
			}
			if(structKeyExists(arguments, "accessedTime")) {
				variables.accessedTime = arguments.accessedTime;
			}
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>
	
		<cfscript>
			if(structKeyExists(variables.attributes, arguments.name)) {
				return variables.attributes.get(arguments.name);
			}
			return "";
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false">
		
		<cfscript>
			return listToArray(structKeyList(variables.attributes));
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false">
		
		<cfscript>
			return variables.creationTime;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getId" output="false">
		
		<cfscript>
			return "" & variables.sessionid;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="getInvalidated" output="false"
	            hint="Gets the invalidated.">
		
		<cfscript>
			return variables.invalidated;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getLastAccessedTime" output="false">
		
		<cfscript>
			return variables.accessedTime;
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
			ret = [];
			return ret;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="invalidate" output="false">
		
		<cfscript>
			variables.invalidated = true;
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
			variables.attributes.put(arguments.name, arguments.value);
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
			variables.accessedTime = arguments.time;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setCreationTime" output="false">
		<cfargument required="true" type="numeric" name="time"/>
	
		<cfscript>
			variables.creationTime = arguments.time;
		</cfscript>
		
	</cffunction>
	
</cfcomponent>
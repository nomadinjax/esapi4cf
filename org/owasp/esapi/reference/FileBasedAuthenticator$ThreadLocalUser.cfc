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
<cfcomponent extends="org.owasp.esapi.util.ThreadLocal" output="false" hint="The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an application. Otherwise, each thread would have to pass the User object through the calltree to any methods that need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore, the ThreadLocal approach simplifies things greatly. As a possible extension, one could create a delegation framework by adding another ThreadLocal to hold the delegating user identity.">

	<cfscript>
		variables.ESAPI = "";
	</cfscript>
	
	<cffunction access="public" returntype="FileBasedAuthenticator$ThreadLocalUser" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
	
		<cfscript>
			variables.ESAPI = arguments.ESAPI;
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="initialValue" output="false">
		
		<cfscript>
			return createObject("component", "org.owasp.esapi.User$ANONYMOUS").init(variables.ESAPI);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="User" name="getUser" output="false">
		
		<cfscript>
			return super.get();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setUser" output="false">
		<cfargument required="true" type="org.owasp.esapi.User" name="newUser"/>
	
		<cfscript>
			super.set(arguments.newUser);
		</cfscript>
		
	</cffunction>
	
</cfcomponent>
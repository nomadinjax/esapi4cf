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
<cfcomponent implements="esapi4cf.org.owasp.esapi.HttpSession" extends="esapi4cf.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.session = "";
	</cfscript>

	<cffunction access="public" returntype="SafeSession" name="init" output="false">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" name="session"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			instance.session = arguments.session;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.session.getAttribute( javaCast( "string", arguments.name ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false">

		<cfscript>
			var local = {};
			local.ret = [];
			local.atts = instance.session.getAttributeNames();
			if (isArray(local.atts)) {
				local.ret = local.atts;
			}
			else {
				if (structKeyExists(local, "atts")) {
					while (local.atts.hasNext()) {
						arrayAppend(local.ret, local.atts.next());
					}
				}
			}
			return local.ret;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false">

		<cfscript>
			return instance.session.getCreationTime();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getId" output="false">

		<cfscript>
			return instance.session.getId();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLastAccessedTime" output="false">

		<cfscript>
			return instance.session.getLastAccessedTime();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getMaxInactiveInterval" output="false">

		<cfscript>
			return instance.session.getMaxInactiveInterval();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getServletContext" output="false">

		<cfscript>
			return instance.session.getServletContext();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getSessionContext" output="false" hint="Deprecated. No replacement.">

		<cfscript>
			return instance.session.getSessionContext();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValue" output="false" hint="Deprecated in favor of getAttribute(name).">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.session.getValue( javaCast( "string", arguments.name ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getValueNames" output="false"
	            hint="Deprecated in favor of getAttributeNames().">

		<cfscript>
			return instance.session.getValueNames();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="invalidate" output="false">

		<cfscript>
			/*
			* Discussion:
			* The way CF sessions function is they use the J2EE sessions which contain a struct.  The keys of that struct
			* are the CF application names which contain the session variables that we commonly refer to via the CF session scope.
			* This means that we cannot use the below for multiple reasons:
			*
			*     instance.session.invalidate();
			*
			* 1) You cannot destroy the session and create a session on the same request, as creating a new session involves sending session cookies
			*     back. http://livedocs.adobe.com/coldfusion/8/htmldocs/help.html?content=sharedVars_17.html
			* 2) The instance.session references the J2EE session which contains all of your CF applications. Invalidating instance.session would
			*     kill all CF application sessions, not just the one you are actively using esapi4cf within.
			* 3) Currently when you do call invalidate(), any references to the session scope after this call within the same request result in a
			*     "Invalid session" error being thrown.
			*
			* What are the alternatives?
			*     http://stackoverflow.com/questions/3686116/invalidate-session-how-to-use-correctly
			*     http://www.bennadel.com/blog/1847-Explicitly-Ending-A-ColdFusion-Session.htm
			*     https://github.com/misterdai/cfbackport/blob/master/cf10.cfm#SessionInvalidate
			*
			* Possibilities?
			*     structClear(instance.session[local.applicationName]);
			*     instance.session[local.applicationName].setMaxInterval(javaCast("long", 1)); -- throws CF exception 'setMaxInterval' undefined
			*
			* Are there any better (or more secure) ways to handle this???
			*
			* CF10 has a sessionInvalidate() method.  Will this work and can we mimic this in CF8/9?
			*/
			local.applicationName = instance.ESAPI.httpUtilities().getApplicationName();
			// this technique will not harm session state for other CF applications
			if(local.applicationName != "") {
				// Railo sessions are empty unless you have explicitly set session vars so check for it first
				if(structKeyExists(instance.session, local.applicationName)) {
					structClear(instance.session[local.applicationName]);
				}
			}
			else {
				structClear(instance.session);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isNew" output="false">

		<cfscript>
			return instance.session.isNew();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="putValue" output="false"
	            hint="Deprecated in favor of setAttribute(name, value).">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="value"/>

		<cfscript>
			return instance.session.putValue( javaCast( "string", arguments.name ), arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.session.removeAttribute( javaCast( "string", arguments.name ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeValue" output="false"
	            hint="Deprecated in favor of removeAttribute(name).">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.session.removeValue( javaCast( "string", arguments.name ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="value"/>

		<cfscript>
			return instance.session.setAttribute( javaCast( "string", arguments.name ), arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setMaxInactiveInterval" output="false">
		<cfargument required="true" type="numeric" name="interval"/>

		<cfscript>
			return instance.session.setMaxInactiveInterval( javaCast( "int", arguments.interval ) );
		</cfscript>

	</cffunction>

</cfcomponent>
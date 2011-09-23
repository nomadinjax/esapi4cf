<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.HttpSession" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.session = "";
	</cfscript>

	<cffunction access="public" returntype="SecurityWrapperSession" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="any" name="session" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.session = arguments.session;

    		return this;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getAttribute" output="false" hint="Returns the object bound with the specified name in this session, or null if no object is bound under the name.">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			local.applicationName = instance.ESAPI.httpUtilities().getApplicationName();
			if ( local.applicationName != "" ) {
				if (!isNull(instance.session.getAttribute(local.applicationName)) && structKeyExists(instance.session.getAttribute(local.applicationName), arguments.name)) {
					return instance.session.getAttribute(local.applicationName)[arguments.name];
				}
			}
			else {
				if (structKeyExists(instance.session, arguments.name)) {
					return instance.session[arguments.name];
				}
			}

			return "";
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false" hint="Returns an Enumeration of String objects containing the names of all the objects bound to this session.">
		<cfscript>
			local.an = instance.session.getAttributeNames();
			local.ret = [];
			while (!isNull(local.an) && local.an.hasMoreElements()) {
				arrayAppend(local.ret, local.an.nextElement());
			}
			return local.ret;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false" hint="Returns the time when this session was created, measured in milliseconds since midnight January 1, 1970 GMT.">
		<cfscript>
			return instance.session.getCreationTime();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getId" output="false" hint="Returns a string containing the unique identifier assigned to this session.">
		<cfscript>
			return instance.session.getId();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLastAccessedTime" output="false" hint="Returns the last time the client sent a request associated with this session, as the number of milliseconds since midnight January 1, 1970 GMT, and marked by the time the container received the request.">
		<cfscript>
			return instance.session.getLastAccessedTime();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxInactiveInterval" output="false" hint="Returns the maximum time interval, in seconds, that the servlet container will keep this session open between client accesses.">
		<cfscript>
			instance.session.getMaxInactiveInterval();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getServletContext" output="false" hint="javax.servlet.ServletContext: Returns the ServletContext to which this session belongs.">
		<cfscript>
			return instance.session.getServletContext();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="invalidate" output="false" hint="Invalidates this session then unbinds any objects bound to it.">
		<cfscript>
			/*
			* Discussion:
			* The way CF sessions function is they use the J2EE sessions which contain a struct.  The keys of that struct
			* are the CF application names which contain the session variables that we commonly refer to via the CF session scope.
			* This means that we cannot use the below for multiple reasons:
			* 
			* 	instance.session.invalidate();
			* 
			* 1) You cannot destroy the session and create a session on the same request, as creating a new session involves sending session cookies
			* 	back. http://livedocs.adobe.com/coldfusion/8/htmldocs/help.html?content=sharedVars_17.html
			* 2) The instance.session references the J2EE session which contains all of your CF applications. Invalidating instance.session would
			* 	kill all CF application sessions, not just the one you are actively using CFESAPI within.
			* 3) Currently when you do call invalidate(), any references to the session scope after this call within the same request result in a
			* 	"Invalid session" error being thrown.
			* 
			* What are the alternatives?
			* 	http://stackoverflow.com/questions/3686116/invalidate-session-how-to-use-correctly
			* 	http://www.bennadel.com/blog/1847-Explicitly-Ending-A-ColdFusion-Session.htm
			* 
			* Possibilities?
			* 	structClear(instance.session[local.applicationName]);
			* 	instance.session[local.applicationName].setMaxInterval(javaCast("long", 1)); -- throws CF exception 'setMaxInterval' undefined
			* 
			* Are there any better (or more secure) ways to handle this???
			*/
			local.applicationName = instance.ESAPI.httpUtilities().getApplicationName();
			// this technique will not harm session state for other CF applications
			if ( local.applicationName != "" ) {
				structClear(instance.session[local.applicationName]);
			}
			else {
				structClear(instance.session);
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isNew" output="false" hint="Returns true if the client does not yet know about the session or if the client chooses not to join the session.">
		<cfscript>
			return instance.session.isNew();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="removeAttribute" output="false" hint="Removes the object bound with the specified name from this session.">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			return instance.session.removeAttribute(arguments.name);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setAttribute" output="false" hint="Binds an object to this session, using the name specified.">
		<cfargument type="String" name="name" required="true">
		<cfargument type="any" name="value" required="true">
		<cfscript>
			local.applicationName = instance.ESAPI.httpUtilities().getApplicationName();
			if (local.applicationName != "") {
				if (!isNull(instance.session.getAttribute(local.applicationName))) {
					instance.session.getAttribute(local.applicationName)[arguments.name] = arguments.value;
				}
			}
			else {
				instance.session[arguments.name] = arguments.value;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setMaxInactiveInterval" output="false" hint="Specifies the time, in seconds, between client requests before the servlet container will invalidate this session.">
		<cfargument type="numeric" name="interval" required="true">
		<cfscript>
			instance.session.setMaxInactiveInterval(arguments.interval);
		</cfscript>
	</cffunction>


</cfcomponent>

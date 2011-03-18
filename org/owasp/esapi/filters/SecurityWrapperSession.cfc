<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.HttpSession" output="false">

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


	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false">
		<cfscript>
			return instance.session.getCreationTime();
		</cfscript>
	</cffunction>

	<!--- public java.lang.String getId(); --->

	<cffunction access="public" returntype="numeric" name="getLastAccessedTime" output="false">
		<cfscript>
			return instance.session.getLastAccessedTime();
		</cfscript>
	</cffunction>

	<!--- public javax.servlet.ServletContext getServletContext(); --->
	<!--- public void setMaxInactiveInterval(int interval); --->
	<!--- public int getMaxInactiveInterval(); --->

	<cffunction access="public" returntype="any" name="getAttribute" output="false">
		<cfargument type="String" name="key" required="true">
		<cfscript>
			local.applicationName = instance.ESAPI.httpUtilities().getApplicationName();
			if ( local.applicationName != "" ) {
				if (!isNull(instance.session.getAttribute(local.applicationName)) && structKeyExists(instance.session.getAttribute(local.applicationName), arguments.key)) {
					return instance.session.getAttribute(local.applicationName)[arguments.key];
				}
			}
			else {
				if (structKeyExists(instance.session, arguments.key)) {
					return instance.session[arguments.key];
				}
			}

			return "";
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getAttributeNames" output="false">
		<cfscript>
			return instance.session.getAttributeNames();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument type="String" name="key" required="true">
		<cfargument type="any" name="object" required="true">
		<cfscript>
			local.applicationName = instance.ESAPI.httpUtilities().getApplicationName();
			if (local.applicationName != "") {
				if (!isNull(instance.session.getAttribute(local.applicationName))) {
					instance.session.getAttribute(local.applicationName)[arguments.key] = arguments.object;
				}
			}
			else {
				instance.session[arguments.key] = arguments.object;
			}
		</cfscript>
	</cffunction>

	<!--- public void removeAttribute(java.lang.String key); --->

	<cffunction access="public" returntype="void" name="invalidate" output="false">
		<cfscript>
			// causes errors after its called
			//instance.session.invalidate();

			local.applicationName = instance.ESAPI.httpUtilities().getApplicationName();
			if (local.applicationName != "") {
				local.jTracker = createObject("java", "coldfusion.runtime.SessionTracker");
				// TODO: test this more to ensure it is doing what we are expercting
				// doesn't help that Adobe has no docs on their Java CF classes

				//writedump(instance.session);
				local.jTracker.cleanUp(instance.session, local.applicationName);
				//writedump(var=instance.session,abort=true);
			}
		</cfscript>
	</cffunction>

	<!--- public boolean isNew(); --->

</cfcomponent>

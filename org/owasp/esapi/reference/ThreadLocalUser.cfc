<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an application.">

	<cfscript>
		instance.ESAPI = '';
	</cfscript>

	<cffunction access="public" returntype="ThreadLocalUser" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getUser" output="false" hint="cfesapi.org.owasp.esapi.User">
		<cfscript>
			local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(true);
			return local.session.getAttribute(instance.ESAPI.authenticator().USER);
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setUser" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="newUser" required="true">
		<cfscript>
            local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(true);
			local.session.setAttribute(instance.ESAPI.authenticator().USER, arguments.newUser);
        </cfscript>
	</cffunction>


</cfcomponent>

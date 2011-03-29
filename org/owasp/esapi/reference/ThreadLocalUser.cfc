<cfcomponent extends="cfesapi.org.owasp.esapi.util.ThreadLocal" output="false" hint="The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an application.">

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


	<cffunction access="public" returntype="User" name="initialValue" output="false">
		<cfscript>
            return createObject("component", "AnonymousUser").init(instance.ESAPI);
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getUser" output="false" hint="cfesapi.org.owasp.esapi.User">
		<cfscript>
			return super.get();
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setUser" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="newUser" required="true">
		<cfscript>
            super.set(arguments.newUser);
        </cfscript>
	</cffunction>


</cfcomponent>

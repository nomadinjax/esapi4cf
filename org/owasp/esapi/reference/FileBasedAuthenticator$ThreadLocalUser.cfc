<cfcomponent extends="cfesapi.org.owasp.esapi.util.ThreadLocal" output="false">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="FileBasedAuthenticator$ThreadLocalUser" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="initialValue" output="false">

		<cfscript>
			return createObject( "component", "cfesapi.org.owasp.esapi.User$ANONYMOUS" ).init( instance.ESAPI );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="User" name="getUser" output="false">

		<cfscript>
			return super.get();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setUser" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="newUser"/>

		<cfscript>
			super.set( arguments.newUser );
		</cfscript>

	</cffunction>

</cfcomponent>
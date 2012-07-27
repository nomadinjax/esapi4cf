<cfcomponent extends="cfesapi.org.owasp.esapi.util.ThreadLocal" output="false" hint="Defines the ThreadLocalResponse to store the current response for this thread.">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="DefaultHTTPUtilities$ThreadLocalResponse" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="initialValue" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" type="cfesapi.org.owasp.esapi.filters.SafeResponse" name="getResponse" output="false">

		<cfscript>
			return super.get();
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="setResponse" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.filters.SafeResponse" name="newResponse"/>

		<cfscript>
			super.set( arguments.newResponse );
		</cfscript>

	</cffunction>

</cfcomponent>
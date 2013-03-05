<cfcomponent extends="esapi4cf.org.owasp.esapi.util.ThreadLocal" output="false" hint="Defines the ThreadLocalRequest to store the current request for this thread.">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="DefaultHTTPUtilities$ThreadLocalRequest" name="init" output="false">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>

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

	<cffunction access="public" name="getRequest" output="false">

		<cfscript>
			return super.get();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRequest" output="false">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.filters.SafeRequest" name="newRequest"/>

		<cfscript>
			super.set( arguments.newRequest );
		</cfscript>

	</cffunction>

</cfcomponent>
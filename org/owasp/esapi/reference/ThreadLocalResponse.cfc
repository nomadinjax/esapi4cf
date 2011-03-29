<cfcomponent extends="cfesapi.org.owasp.esapi.util.ThreadLocal" output="false" hint="Defines the ThreadLocalResponse to store the current response for this thread.">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="ThreadLocalResponse" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.HttpServletResponse" name="getResponse" output="false">
		<cfscript>
			return super.get();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.filters.SecurityWrapperResponse" name="initialValue" output="false">
		<cfscript>
            return createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperResponse").init(instance.ESAPI, getPageContext().getResponse());
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setResponse" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="newResponse" required="true">
		<cfscript>
			super.set(arguments.newResponse);
	    </cfscript>
	</cffunction>


</cfcomponent>

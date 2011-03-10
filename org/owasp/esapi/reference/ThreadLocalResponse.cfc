<cfcomponent output="false" hint="Defines the ThreadLocalResponse to store the current response for this thread.">

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
		    if ( !(structKeyExists(request, "currentResponse") && isInstanceOf(request.currentResponse, "cfesapi.org.owasp.esapi.HttpServletResponse")) ) {
				this.setResponse( createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperResponse").init(instance.ESAPI, getPageContext().getResponse()) );
			}
			return request.currentResponse;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setResponse" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="newResponse" required="true">
		<cfscript>
	    	request.currentResponse = arguments.newResponse;
	    </cfscript>
	</cffunction>


</cfcomponent>

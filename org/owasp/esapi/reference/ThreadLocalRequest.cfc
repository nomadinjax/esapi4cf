<cfcomponent output="false" hint="Defines the ThreadLocalRequest to store the current request for this thread.">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="ThreadLocalRequest" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.HttpServletRequest" name="getRequest" output="false">
		<cfscript>
	    	if ( !(structKeyExists(request, "currentRequest") && isInstanceOf(request.currentRequest, "cfesapi.org.owasp.esapi.HttpServletRequest")) ) {
				this.setRequest( createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, getPageContext().getRequest()) );
			}
			return request.currentRequest;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setRequest" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="newRequest" required="true">
		<cfscript>
	    	request.currentRequest = arguments.newRequest;
	    </cfscript>
	</cffunction>


</cfcomponent>

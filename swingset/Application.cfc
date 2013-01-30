<cfcomponent extends="esapi4cf.swingset.org.corfield.framework" output="false">

	<cffunction access="public" returntype="void" name="setupApplication" output="false">
		<cfscript>
			// allows the FW/1 'reload' to also reload ESAPI for us
			structDelete(application, "ESAPI");
			ESAPI().securityConfiguration().setResourceDirectory( "/esapi4cf/swingset/WEB-INF/.esapi/" );
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="setupRequest" output="false">
		<cfscript>
			// Initialize ESAPI request and response
			ESAPI().httpUtilities().setCurrentHTTP( getPageContext().getRequest(), getPageContext().getResponse() );
		</cfscript>
	</cffunction>

	<cffunction access="private" returntype="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI" output="false">
		<cfif not structKeyExists(application, "ESAPI")>
			<cflock timeout="5" scope="application" type="exclusive">
				<cfif not structKeyExists(application, "ESAPI")>
					<cfset application.ESAPI = createObject("component", "esapi4cf.org.owasp.esapi.ESAPI").init()/>
				</cfif>
			</cflock>
		</cfif>
		<cfreturn application.ESAPI/>
	</cffunction>

</cfcomponent>
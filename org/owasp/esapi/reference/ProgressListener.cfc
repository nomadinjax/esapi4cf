<cfcomponent output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		instance.session = "";

		instance.megaBytes = -1;
		instance.progress = 0;
	</cfscript>

	<cffunction access="public" returntype="ProgressListener" name="init" output="false" hint="Create a progress listener">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="session" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("HTTPUtilities");

			instance.session = arguments.session;

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="update" output="false">
		<cfargument type="numeric" name="pBytesRead" required="true">
		<cfargument type="numeric" name="pContentLength" required="true">
		<cfargument type="numeric" name="pItems" required="true">
		<cfscript>
			if (arguments.pItems == 0) {
				return;
			}
			local.mBytes = arguments.pBytesRead / 1000000;
			if (instance.megaBytes == local.mBytes) {
				return;
			}
			instance.megaBytes = local.mBytes;
			instance.progress = (arguments.pBytesRead / arguments.pContentLength) * 100;
			if ( !isNull(instance.session) ) {
			    instance.session.setAttribute("progress", createObject("java", "java.lang.Long").toString(instance.progress));
			}
			// instance.logger.logSuccess(Logger.SECURITY, "   Item " & arguments.pItems & " (" & instance.progress & "% of " & arguments.pContentLength & " bytes]");
		</cfscript>
	</cffunction>


</cfcomponent>

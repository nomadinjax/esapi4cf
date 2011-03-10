<cfcomponent extends="cfesapi.test.org.owasp.esapi.SecurityConfigurationWrapper" output="false">

	<cfscript>
		instance.allowedExes = "";
		instance.workingDir = "";
	</cfscript>

	<cffunction access="public" returntype="Conf" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.SecurityConfiguration" name="orig" required="true">
		<cfargument type="Array" name="allowedExes" required="true">
		<cfargument type="any" name="workingDir" required="true" hint="java.io.File">
		<cfscript>
			super.init(arguments.orig);
			instance.allowedExes = arguments.allowedExes;
			instance.workingDir = arguments.workingDir;

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAllowedExecutables" output="false">
		<cfscript>
			return instance.allowedExes;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getWorkingDirectory" output="false">
		<cfscript>
			return instance.workingDir;
		</cfscript>
	</cffunction>


</cfcomponent>

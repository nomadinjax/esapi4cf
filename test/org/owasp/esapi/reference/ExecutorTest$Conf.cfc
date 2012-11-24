<cfcomponent extends="cfesapi.test.org.owasp.esapi.SecurityConfigurationWrapper" output="false" hint="Config wrapper to temporarly set the allowedExecutables and workingDirectory.">

	<cfscript>
		instance.allowedExes = [];
		instance.workingDir = "";
	</cfscript>

	<cffunction access="public" returntype="ExecutorTest$Conf" name="init" output="false" hint="Create wrapper with the specified allowed execs and workingDir.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.SecurityConfiguration" name="orig" hint="The configuration to wrap.">
		<cfargument required="true" type="Array" name="allowedExes" hint="The executables to be allowed">
		<cfargument required="true" name="workingDir" hint="The working directory for execution">
		<cfscript>
			super.init(arguments.orig);
			instance.allowedExes = arguments.allowedExes;
			instance.workingDir = arguments.workingDir;

			return this;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="Array" name="getAllowedExecutables" output="false" hint="Override real one with our temporary one.">
		<cfscript>
			return instance.allowedExes;
		</cfscript>
	</cffunction>

	<cffunction access="public" name="getWorkingDirectory" output="false" hint="Override real one with our temporary one.">
		<cfscript>
			return instance.workingDir;
		</cfscript>
	</cffunction>

</cfcomponent>
<cfcomponent output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");

		instance.version = "2.0_rc10";
	</cfscript>
	<!---
		// ESAPI
		* expandPath("/cfesapi/esapi/ESAPI-" & instance.version & ".jar"),
		// Custom bridge between CFESAPI and ESAPI for Java
		expandPath("/cfesapi/esapi/libs/cfesapi.jar"),
		// Log4JLogger
		expandPath("/cfesapi/esapi/libs/log4j-1.2.12.jar"),
		// AccessController - ACRPolicyFileLoader#load()
		* expandPath("/cfesapi/esapi/libs/commons-configuration-1.5.jar"),
		// Validator#getValidSafeHTML() - HTMLValidationRule (AntiSamy)
		* expandPath("/cfesapi/esapi/libs/antisamy-1.4.jar"),
		expandPath("/cfesapi/esapi/libs/batik-css-1.7.jar"),
		expandPath("/cfesapi/esapi/libs/nekohtml-1.9.12.jar"),
		expandPath("/cfesapi/esapi/libs/xercesImpl-2.6.2.jar"),
		// HTTPUtilities#getFileUploads()
		* expandPath("/cfesapi/esapi/libs/commons-fileupload-1.2.jar")
	--->
	<!--- public methods --->

	<cffunction access="public" returntype="String" name="version" output="false" hint="Returns the CFESAPI version">
		<cfscript>
			return instance.version;
		</cfscript>
	</cffunction>

	<!--- private methods --->

	<cffunction access="private" returntype="any" name="importClass" output="false">
		<cfargument type="String" name="path" required="true">
		<cfargument type="String" name="name" required="false" default="">
		<cfscript>
			if (len(trim(arguments.name))) {
				local.name = arguments.name;
			}
			else {
				local.name = listLast(arguments.path, ".");
			}

			variables[local.name] = createObject("java", arguments.path);
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="importCFC" output="false">
		<cfargument type="String" name="path" required="true">
		<cfargument type="String" name="name" required="false" default="">
		<cfscript>
			if (len(trim(arguments.name))) {
				local.name = arguments.name;
			}
			else {
				local.name = listLast(arguments.path, ".");
			}

			variables[local.name] = createObject("component", arguments.path);
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="assert" output="false">
		<cfargument type="boolean" name="boolean_expression" required="true">
		<cfargument type="String" name="string_expression" required="false">
		<cfscript>
			if (!arguments.boolean_expression) {
				throw(object=createObject("java", "java.lang.AssertionError").init(arguments.string_expression));
			}
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="binary" name="newByte" outuput="false">
		<cfargument type="numeric" name="len" required="true">
		<cfscript>
			StringBuilder = createObject("java", "java.lang.StringBuilder").init();
			StringBuilder.setLength(arguments.len);
			return StringBuilder.toString().getBytes();
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="numeric" name="newLong" output="false">
		<cfargument type="numeric" name="long" required="true">
		<cfscript>
			return createObject("java", "java.lang.Long").init(arguments.long);
		</cfscript>
	</cffunction>


</cfcomponent>

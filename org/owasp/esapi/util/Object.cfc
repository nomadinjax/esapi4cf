<cfcomponent output="false">

	<cfscript>
		instance.version = "2.0_rc10";
		instance.javaLoaderKey = "cfesapi-" & instance.version & "-javaloader";
	</cfscript>
	<cfif not structKeyExists(server, instance.javaLoaderKey)>
		<cflock name="#instance.javaLoaderKey#" throwontimeout="true" timeout="5">
			<cfscript>
				if (!structKeyExists(server, instance.javaLoaderKey)) {
					server[instance.javaLoaderKey] = createObject("component", "javaloader.JavaLoader").init([
						// ESAPI
						expandPath("/cfesapi/esapi/ESAPI-" & instance.version & ".jar"),
						// Custom bridge between CFESAPI and ESAPI for Java
						expandPath("/cfesapi/esapi/libs/cfesapi.jar"),
						// Log4J
						expandPath("/cfesapi/esapi/libs/log4j-1.2.12.jar"),
						// AntiSamy
						expandPath("/cfesapi/esapi/libs/xercesImpl-2.6.2.jar"),
						expandPath("/cfesapi/esapi/libs/batik-css-1.7.jar"),
						expandPath("/cfesapi/esapi/libs/nekohtml-1.9.12.jar"),
						expandPath("/cfesapi/esapi/libs/antisamy-1.4.jar"),
						// File Upload
						expandPath("/cfesapi/esapi/libs/commons-fileupload-1.2.jar")
					]);
				}
			</cfscript>
		</cflock>
	</cfif>
	<!--- public methods --->

	<cffunction access="public" returntype="String" name="version" output="false" hint="Returns the CFESAPI version">
		<cfscript>
			return instance.version;
		</cfscript>
	</cffunction>

	<!--- private methods --->

	<cffunction access="private" returntype="javaloader.JavaLoader" name="javaLoader" output="false" hint="Returns the JavaLoader object used by CFESAPI">
		<cfscript>
			return server[instance.javaLoaderKey];
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="importClass" output="false">
		<cfargument type="String" name="path" required="true">
		<cfargument type="String" name="name" required="false" default="">
		<cfargument type="javaloader.JavaLoader" name="javaloader" required="false">
		<cfscript>
			if (len(trim(arguments.name))) {
				local.name = arguments.name;
			}
			else {
				local.name = listLast(arguments.path, ".");
			}

			if (structKeyExists(arguments, "javaloader")) {
				variables[local.name] = arguments.javaloader.create(arguments.path);
			}
			else {
				variables[local.name] = createObject("java", arguments.path);
			}
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

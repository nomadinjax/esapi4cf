<cfcomponent extends="mxunit.framework.TestCase" output="false">

	<!--- delete the users.txt file as running all these tests just once creates over 30+ users; the more users, the longer the tests take --->
	<cfscript>
		filePath = expandPath("/cfesapi/esapi/configuration/.esapi/users.txt");
		if (fileExists(filePath)) {
			try {
				fileDelete(filePath);
			} catch (any e) {}
		}
	</cfscript>

	<cfscript>
		instance.version = "2.0_rc10";
		instance.javaLoaderKey = "cfesapi-" & instance.version & "-javaloader-test";
	</cfscript>
	<cfif not structKeyExists(server, instance.javaLoaderKey)>
		<cflock name="#instance.javaLoaderKey#" throwontimeout="true" timeout="5">
			<cfscript>
				if (!structKeyExists(server, instance.javaLoaderKey)) {
					server[instance.javaLoaderKey] = createObject("component", "javaloader.JavaLoader").init([
						// ESAPI
						expandPath("/cfesapi/esapi/ESAPI-" & instance.version & ".jar")
					]);
				}
			</cfscript>
		</cflock>
	</cfif>
	<!--- private methods --->

	<cffunction access="private" returntype="javaloader.JavaLoader" name="javaLoader" output="false" hint="Returns the JavaLoader object used by CFESAPI">
		<cfscript>
			return server[instance.javaLoaderKey];
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


</cfcomponent>

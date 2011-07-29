<cfcomponent extends="mxunit.framework.TestCase" output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");

		// delete the users.txt file as running all these tests just once creates tons of users
		// the more users, the longer the tests take
		filePath = expandPath("/cfesapi/esapi/configuration/.esapi/users.txt");
		if (fileExists(filePath)) {
			try {
				fileDelete(filePath);
			}
			catch (Any e) {}
		}

		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(session);
			structClear(request);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			structClear(session);
			structClear(request);
		</cfscript>
	</cffunction>

	<!--- private methods --->

	<cffunction access="private" returntype="binary" name="newByte" outuput="false">
		<cfargument type="numeric" name="len" required="true">
		<cfscript>
			StringBuilder = createObject("java", "java.lang.StringBuilder").init();
			StringBuilder.setLength(arguments.len);
			return StringBuilder.toString().getBytes();
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="string" name="toUnicode" output="false" description="Convert Unicode in to string characters">
		<cfargument type="string" name="string" required="true">
		<cfscript>
		 	local.ret = "";
		 	for (local.i=1; local.i <= len(arguments.string); local.i++) {
		 		local.thisChr = mid(arguments.string, local.i, 6);
		 		if (left(local.thisChr, 2) == "\u") {
			 		local.ret = local.ret & chr(inputBaseN(right(local.thisChr, 4), 16));
			 		local.i = local.i+5;
		 		}
				else {
		 			local.ret = local.ret & left(local.thisChr, 1);
		 		}
		 	}
		 	return local.ret;
		 </cfscript>
	</cffunction>


</cfcomponent>

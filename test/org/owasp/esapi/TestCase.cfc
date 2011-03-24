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
	</cfscript>
	<!--- private methods --->

	<cffunction access="private" returntype="binary" name="newByte" outuput="false">
		<cfargument type="numeric" name="len" required="true">
		<cfscript>
			StringBuilder = createObject("java", "java.lang.StringBuilder").init();
			StringBuilder.setLength(arguments.len);
			return StringBuilder.toString().getBytes();
		</cfscript>
	</cffunction>


</cfcomponent>

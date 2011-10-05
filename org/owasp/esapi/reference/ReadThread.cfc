<!---
	/**
	* OWASP Enterprise Security API (ESAPI)
	* 
	* This file is part of the Open Web Application Security Project (OWASP)
	* Enterprise Security API (ESAPI) project. For details, please see
	* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
	*
	* Copyright (c) 2011 - The OWASP Foundation
	* 
	* The ESAPI is published by OWASP under the BSD license. You should read and accept the
	* LICENSE before you use, modify, and/or redistribute this software.
	* 
	* @author Damon Miller
	* @created 2011
	*/
	--->
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false">

	<cfscript>
    	instance.exception = "";
    	instance.stream = "";
    	instance.buffer = "";
	</cfscript>
 
	<cffunction access="public" returntype="ReadThread" name="init" output="false">
		<cfargument type="any" name="stream" required="true" hint="java.io.InputStream">
		<cfargument type="any" name="buffer" required="true" hint="java.lang.StringBuilder">
		<cfscript>
	   		instance.stream = arguments.stream;
	   		instance.buffer = arguments.buffer;

	   		return this;
	   	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="run" output="false">
		<cfscript>
	   		//try {
	   			readStream(instance.stream, instance.buffer);
	   		//} catch (IOException e) {
	   		//	instance.exception = e;
	   		//}
   		</cfscript> 
	</cffunction>

	<!---<cffunction access="private" returntype="void" name="readStream" output="false" hint="readStream reads lines from an input stream and returns all of them in a single string">
		<cfargument type="any" name="is" required="true" hint="java.io.InputStream: input stream to read from">
		<cfargument type="any" name="sb" required="true" hint="java.lang.StringBuilder: a string containing as many lines as the input stream contains, with newlines between lines">
		<cfscript>
		local.isr = createObject("java", "java.io.InputStreamReader").init(arguments.is);
		local.br = createObject("java", "java.io.BufferedReader").init(local.isr);
		local.line = local.br.readLine();
		writedump(var=local.line,abort=true);
		/*while (!isNull(local.line)) {
		arguments.sb.append(local.line).append('\n');
		local.line = local.br.readLine();
		}*/
		</cfscript>
		</cffunction>
--->

</cfcomponent>

<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
--->
<cfcomponent implements="cfesapi.org.owasp.esapi.Executor" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Executor interface. This implementation is very restrictive. Commands must exactly equal the canonical path to an executable on the system. Valid characters for parameters are codec dependent, but will usually only include alphanumeric, forward-slash, and dash.">
<!---
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.errors.ExecutorException;
--->
	<cfscript>
		instance.ESAPI = "";

		/** The logger. */
		instance.logger = "";

		//instance.MAX_SYSTEM_COMMAND_LENGTH = 2500;
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Executor" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("Executor");

			return this;
		</cfscript>

	</cffunction>

    <cffunction access="public" returntype="String" name="executeSystemCommand" output="false" hint="The reference implementation sets the work directory, escapes the parameters as per the Codec in use, and then executes the command without using concatenation. If there are failures, it will be logged. Privacy Note: Be careful if you pass PII to the executor, as the reference implementation logs the parameters. You MUST change this behavior if you are passing credit card numbers, TIN/SSN, or health information through this reference implementation, such as to a credit card or HL7 gateway.">
		<cfargument required="true" name="executable">
		<cfargument required="true" type="Array" name="params">
		<cfargument required="true" name="workdir">
		<cfargument required="true" name="codec">
		<cfscript>
			var local = {};

	        try {
	            instance.logger.warning(getSecurity("SECURITY"), true, "Initiating executable: " & arguments.executable & " " & arrayToList(arguments.params) & " in " & arguments.workdir);

	            // command must exactly match the canonical path and must actually exist on the file system
	            // using equalsIgnoreCase for Windows, although this isn't quite as strong as it should be
	            if (!arguments.executable.getCanonicalPath().equalsIgnoreCase(arguments.executable.getPath())) {
	                throwException(createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Invalid path to executable file: " & arguments.executable));
	            }
	            if (!arguments.executable.exists()) {
	                throwException(createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "No such executable: " & arguments.executable));
	            }

	            // escape any special characters in the parameters
	            for ( local.i = 0; local.i < arguments.params.size(); local.i++ ) {
	            	local.param = arguments.params.get(i);
	            	arguments.params.set( local.i, instance.ESAPI.encoder().encodeForOS(arguments.codec, local.param));
	            }

	            // working directory must exist
	            if (!arguments.workdir.exists()) {
	                throwException(createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "No such working directory for running executable: " & arguments.workdir.getPath()));
	            }

	            arguments.params.add(0, arguments.executable.getCanonicalPath());
	            local.command = arguments.params;
	            local.process = getJava("java.lang.Runtime").getRuntime().exec(local.command, [], arguments.workdir);

	            // Future - this is how to implement this in Java 1.5+
	            // ProcessBuilder pb = new ProcessBuilder(arguments.params);
	            // Map env = pb.environment();
	            // Security check - clear environment variables!
	            // env.clear();
	            // pb.directory(arguments.workdir);
	            // pb.redirectErrorStream(true);
	            // Process process = pb.start();

	            local.output = readStream( local.process.getInputStream() );
	            local.errors = readStream( local.process.getErrorStream() );
	            if ( local.errors != "" && local.errors.length() > 0 ) {
	            	instance.logger.warning( getSecurity("SECURITY"), false, "Error during system command: " & local.errors );
	            }
	            instance.logger.warning(getSecurity("SECURITY"), true, "System command complete: " & arrayToList(arguments.params));
	            return local.output;
	        } catch (java.lang.Exception e) {
	            throwException(createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Exception thrown during execution of system command: " & e.getMessage(), e));
	        }
    	</cfscript>
	</cffunction>

    <cffunction access="private" returntype="String" name="readStream" output="false" hint="readStream reads lines from an input stream and returns all of them in a single string">
		<cfargument required="true" name="is" hint="input stream to read from">
		<cfscript>
			var local = {};

		    local.isr = getJava("java.io.InputStreamReader").init(arguments.is);
		    local.br = getJava("java.io.BufferedReader").init(local.isr);
		    local.sb = getJava("java.lang.StringBuffer").init();
		    local.line = local.br.readLine();
		    while (structKeyExists( local, "line" )) {
		        local.sb.append(local.line & "\n");
		        local.line = local.br.readLine();
		    }
		    return local.sb.toString();
    	</cfscript>
	</cffunction>

</cfcomponent>

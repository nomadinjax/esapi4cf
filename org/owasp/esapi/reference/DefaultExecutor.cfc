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
<cfcomponent implements="org.owasp.esapi.Executor" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Executor interface. This implementation is very restrictive. Commands must exactly equal the canonical path to an executable on the system. Valid characters for parameters are codec dependent, but will usually only include alphanumeric, forward-slash, and dash.">

	<cfscript>
		variables.ESAPI = "";

		/** The logger. */
		variables.logger = "";

		//variables.MAX_SYSTEM_COMMAND_LENGTH = 2500;
	</cfscript>
 
	<cffunction access="public" returntype="org.owasp.esapi.Executor" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI">
		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("Executor");

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="executeSystemCommand" output="false" hint="The reference implementation sets the work directory, escapes the parameters as per the Codec in use, and then executes the command without using concatenation. If there are failures, it will be logged. Privacy Note: Be careful if you pass PII to the executor, as the reference implementation logs the parameters. You MUST change this behavior if you are passing credit card numbers, TIN/SSN, or health information through this reference implementation, such as to a credit card or HL7 gateway.">
		<cfargument required="true" name="executable">
		<cfargument required="true" type="Array" name="params">
		<cfargument required="true" name="workdir">
		<cfargument required="true" name="codec">
		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var param = "";
			var command = "";
			var process = "";
			var output = "";
			var errors = "";
			
	        try {
	            variables.logger.warning(getSecurity("SECURITY_SUCCESS"), true, "Initiating executable: " & arguments.executable & " " & arrayToList(arguments.params, " ") & " in " & arguments.workdir);

	            // command must exactly match the canonical path and must actually exist on the file system
	            // using equalsIgnoreCase for Windows, although this isn't quite as strong as it should be
	            if (!arguments.executable.getCanonicalPath().equalsIgnoreCase(arguments.executable.getPath())) {
	                throwException(createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI, "Execution failure", "Invalid path to executable file: " & arguments.executable));
	            }
	            if (!arguments.executable.exists()) {
	                throwException(createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI, "Execution failure", "No such executable: " & arguments.executable));
	            }

	            // escape any special characters in the parameters
	            for ( i = 1; i <= arrayLen(arguments.params); i++ ) {
	            	param = arguments.params[i];
	            	arguments.params[i] = variables.ESAPI.encoder().encodeForOS(arguments.codec, param);
	            }

	            // working directory must exist
	            if (!arguments.workdir.exists()) {
	                throwException(createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI, "Execution failure", "No such working directory for running executable: " & arguments.workdir.getPath()));
	            }

	            arrayPrepend(arguments.params, arguments.executable.getCanonicalPath());
	            command = arguments.params;
	            process = newJava("java.lang.Runtime").getRuntime().exec(command, arrayNew(1), arguments.workdir);
	            // Future - this is how to implement this in Java 1.5+
	            // ProcessBuilder pb = new ProcessBuilder(arguments.params);
	            // Map env = pb.environment();
	            // Security check - clear environment variables!
	            // env.clear();
	            // pb.directory(arguments.workdir);
	            // pb.redirectErrorStream(true);
	            // Process process = pb.start();

	            output = readStream( process.getInputStream() );
	            errors = readStream( process.getErrorStream() );
	            if ( errors != "" && errors.length() > 0 ) {
	            	variables.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Error during system command: " & errors );
	            }
	            variables.logger.warning(getSecurity("SECURITY_SUCCESS"), true, "System command complete: " & arrayToList(arguments.params, " "));
	            return output;
	        } catch (java.lang.Exception e) {
	            throwException(createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI, "Execution failure", "Exception thrown during execution of system command: " & e.getMessage(), e));
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="readStream" output="false" hint="readStream reads lines from an input stream and returns all of them in a single string">
		<cfargument required="true" name="is" hint="input stream to read from">
		<cfscript>
		    var isr = newJava("java.io.InputStreamReader").init(arguments.is);
		    var br = newJava("java.io.BufferedReader").init(isr);
		    var sb = newJava("java.lang.StringBuffer").init();
		    var line = br.readLine();
		    while (isDefined("line")) {
		        sb.append(line & "\n");
		        line = br.readLine();
		    }
		    return sb.toString();
    	</cfscript> 
	</cffunction>


</cfcomponent>

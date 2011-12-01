<!--- /**
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
 */ --->
<cfcomponent displayname="DefaultExecutor" extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Executor" output="false"
             hint="Reference implementation of the Executor interface. This implementation is very restrictive. Commands must exactly equal the canonical path to an executable on the system. Valid characters for parameters are codec dependent, but will usually only include alphanumeric, forward-slash, and dash.">

	<cfscript>
		instance.ESAPI = "";

		/** The logger. */
		instance.logger = "";
		instance.codec = "";
		//instance.MAX_SYSTEM_COMMAND_LENGTH = 2500;
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Executor" name="init" output="false"
	            hint="Instantiate a new Executor">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("Executor");

			if(newJava("java.lang.System").getProperty("os.name").indexOf("Windows") != -1) {
				instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Using WindowsCodec for Executor. If this is not running on Windows this could allow injection");
				instance.codec = newJava("org.owasp.esapi.codecs.WindowsCodec").init();
			}
			else {
				instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Using UnixCodec for Executor. If this is not running on Unix this could allow injection");
				instance.codec = newJava("org.owasp.esapi.codecs.UnixCodec").init();
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="executeSystemCommand" output="false" hint="The reference implementation sets the work directory, escapes the parameters as per the Codec in use, and then executes the command without using concatenation. The exact, absolute, canonical path of each executable must be listed as an approved executable in the ESAPI properties. The executable must also exist on the disk. All failures will be logged, along with parameters if specified. Set the logParams to false if you are going to invoke this interface with confidential information.">
		<cfargument required="true" name="executable"/>
		<cfargument required="true" type="Array" name="params"/>
		<cfargument name="workdir" default="#instance.ESAPI.securityConfiguration().getWorkingDirectory()#"/>
		<cfargument name="codec" default="#instance.codec#"/>
		<cfargument type="boolean" name="logParams" default="false"/>
		<cfargument type="boolean" name="redirectErrorStream" default="false"/>

		<cfset var local = {}/>

		<cfscript>
			try {
				// executable must exist
				if(!arguments.executable.exists()) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "No such executable: " & arguments.executable);
					throwError(local.exception);
				}

				// executable must use canonical path
				if(!arguments.executable.isAbsolute()) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Attempt to invoke an executable using a non-absolute path: " & arguments.executable);
					throwError(local.exception);
				}

				// executable must use canonical path
				if(!arguments.executable.getPath() == arguments.executable.getCanonicalPath()) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Attempt to invoke an executable using a non-canonical path: " & arguments.executable);
					throwError(local.exception);
				}

				// exact, absolute, canonical path to executable must be listed in ESAPI configuration
				local.approved = instance.ESAPI.securityConfiguration().getAllowedExecutables();
				if(!local.approved.contains(arguments.executable.getPath())) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Attempt to invoke executable that is not listed as an approved executable in ESAPI configuration: " & arguments.executable.getPath() & " not listed in " & local.approved);
					throwError(local.exception);
				}

				// escape any special characters in the parameters
				for(local.i = 1; local.i <= arguments.params.size(); local.i++) {
					local.param = arguments.params[local.i];
					arguments.params[local.i] = instance.ESAPI.encoder().encodeForOS(arguments.codec, local.param);
				}

				// working directory must exist
				if(!arguments.workdir.exists()) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "No such working directory for running executable: " & arguments.workdir.getPath());
					throwError(local.exception);
				}

				// set the command into the list and create command array
				arguments.params.add(0, arguments.executable.getCanonicalPath());

				// Legacy - this is how to implement in Java 1.4
				// String[] command = (String[])params.toArray( new String[0] );
				// Process process = Runtime.getRuntime().exec(command, new String[0], workdir);
				// The following is host to implement in Java 1.5+
				local.pb = newJava("java.lang.ProcessBuilder").init(arguments.params);
				local.env = local.pb.environment();
				local.env.clear();// Security check - clear environment variables!
				local.pb.directory(arguments.workdir);
				local.pb.redirectErrorStream(arguments.redirectErrorStream);

				if(arguments.logParams) {
					instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Initiating executable: " & arguments.executable & " " & arguments.params & " in " & arguments.workdir);
				}
				else {
					instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Initiating executable: " & arguments.executable & " [sensitive parameters obscured] in " & arguments.workdir);
				}

				local.outputBuffer = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
				local.errorsBuffer = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
				local.process = local.pb.start();
				try {
					local.errorReader = "";
					if(!arguments.redirectErrorStream) {
						local.errorReader = newComponent("cfesapi.org.owasp.esapi.reference.DefaultExecutor$ReadThread").init(local.process.getErrorStream(), local.errorsBuffer);
						local.errorReader.start();
					}
					else {
						local.errorReader = null;
					}
					readStream(local.process.getInputStream(), local.outputBuffer);
					if(structKeyExists(local, "errorReader")) {
						local.errorReader.join();
						if(structKeyExists(local.errorReader, "exception")) {
							throwError(local.errorReader.exception);
						}
					}
					local.process.waitFor();
				}
				catch(java.lang.Throwable e) {
					local.process.destroy();
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Exception thrown during execution of system command: " & e.getMessage(), e);
					throwError(local.exception);
				}

				local.output = local.outputBuffer.toStringESAPI();
				local.errors = local.errorsBuffer.toStringESAPI();
				local.exitValue = local.process.exitValue();
				if(structKeyExists(local, "errors") && local.errors.length() > 0) {
					local.logErrors = local.errors;
					local.MAX_LEN = 256;
					if(local.logErrors.length() > local.MAX_LEN) {
						local.logErrors = local.logErrors.substring(0, local.MAX_LEN) & "(truncated at " & local.MAX_LEN & " characters)";
					}
					instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Error during system command: " & local.logErrors);
				}
				if(local.exitValue != 0) {
					instance.logger.warning(newJava("org.owasp.esapi.Logger").EVENT_FAILURE, "System command exited with non-zero status: " & local.exitValue);
				}

				instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "System command complete");
				return newJava("org.owasp.esapi.ExecuteResult").init(local.exitValue, local.output, local.errors);
			}
			catch(java.io.IOException e) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Exception thrown during execution of system command: " & e.getMessage(), e);
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="readStream" output="false"
	            hint="readStream reads lines from an input stream and returns all of them in a single string">
		<cfargument required="true" name="inputStream" hint="input stream to read from"/>
		<cfargument required="true" name="sb"/>

		<cfset var local = {}/>

		<cfscript>
			local.isr = newJava("java.io.InputStreamReader").init(arguments.inputStream);
			local.br = newJava("java.io.BufferedReader").init(local.isr);
			local.line = local.br.readLine();
			while(structKeyExists(local, "line")) {
				sb.append(local.line).append("\n");
				local.line = local.br.readLine();
			}
		</cfscript>

	</cffunction>

</cfcomponent>
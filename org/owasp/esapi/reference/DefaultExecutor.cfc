<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.Executor" output="false" hint="Reference implementation of the Executor interface. This implementation is very restrictive. Commands must exactly equal the canonical path to an executable on the system. ">

	<cfscript>
		instance.ESAPI = "";

		/* The logger. */
    	instance.logger = "";
    	instance.codec = "";
	</cfscript>

	<cffunction access="public" returntype="DefaultExecutor" name="init" output="false" hint="Instantiate a new Executor">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("Executor");

			if ( createObject("java", "java.lang.System").getProperty("os.name").indexOf("Windows") != -1 ) {
				instance.logger.warning( javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Using WindowsCodec for Executor. If this is not running on Windows this could allow injection" );
				instance.codec = javaLoader().create("org.owasp.esapi.codecs.WindowsCodec").init();
			} else {
				instance.logger.warning( javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Using UnixCodec for Executor. If this is not running on Unix this could allow injection" );
				instance.codec = javaLoader().create("org.owasp.esapi.codecs.UnixCodec").init();
			}

			return this;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="executeSystemCommand" output="false" hint="org.owasp.esapi.ExecuteResult: The reference implementation sets the work directory, escapes the parameters as per the Codec in use, and then executes the command without using concatenation. The exact, absolute, canonical path of each executable must be listed as an approved executable in the ESAPI properties. The executable must also exist on the disk. All failures will be logged, along with parameters if specified. Set the logParams to false if you are going to invoke this interface with confidential information.">
		<cfargument type="any" name="executable" required="true" hint="java.io.File">
		<cfargument type="Array" name="params" required="true">
		<cfargument type="any" name="workdir" required="false" default="#instance.ESAPI.securityConfiguration().getWorkingDirectory()#" hint="java.io.File">
		<cfargument type="any" name="codec" required="false" default="#instance.codec#" hint="org.owasp.esapi.codecs.Codec">
		<cfargument type="boolean" name="logParams" required="false" default="false">
		<cfargument type="boolean" name="redirectErrorStream" required="false" default="false">
		<cfscript>
	    	try {
	            // executable must exist
	            if (!arguments.executable.exists()) {
	                e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "No such executable: " & arguments.executable);
            		throw(message=e.getMessage(), type=e.getType());
	            }

	            // executable must use canonical path
	            if ( !arguments.executable.isAbsolute() ) {
	                e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Attempt to invoke an executable using a non-absolute path: " & arguments.executable);
            		throw(message=e.getMessage(), type=e.getType());
	            }

	            // executable must use canonical path
	            if ( !arguments.executable.getPath() == arguments.executable.getCanonicalPath() ) {
	            	e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Attempt to invoke an executable using a non-canonical path: " & arguments.executable);
            		throw(message=e.getMessage(), type=e.getType());
	        	}

	            // exact, absolute, canonical path to executable must be listed in ESAPI configuration
	            local.approved = instance.ESAPI.securityConfiguration().getAllowedExecutables();
	            if (!local.approved.contains(arguments.executable.getPath())) {
	                e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Attempt to invoke executable that is not listed as an approved executable in ESAPI configuration: " & arguments.executable.getPath() & " not listed in " & local.approved );
            		throw(message=e.getMessage(), type=e.getType());
	            }

	            // escape any special characters in the parameters
	            for ( local.i = 0; local.i < arguments.params.size(); local.i++ ) {
	            	local.param = arguments.params.get(local.i);
	            	arguments.params.set( local.i, instance.ESAPI.encoder().encodeForOS(arguments.codec, local.param));
	            }

	            // working directory must exist
	            if (!arguments.workdir.exists()) {
	                e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "No such working directory for running executable: " & arguments.workdir.getPath());
            		throw(message=e.getMessage(), type=e.getType());
	            }

	            // set the command into the list and create command array
	            arguments.params.add(0, arguments.executable.getCanonicalPath());

	            // Legacy - this is how to implement in Java 1.4
	            // String[] command = (String[])params.toArray( new String[0] );
	            // Process process = Runtime.getRuntime().exec(command, new String[0], workdir);

	            // The following is host to implement in Java 1.5+
	            local.pb = createObject("java", "java.lang.ProcessBuilder").init(arguments.params);
	            local.env = local.pb.environment();
	            local.env.clear();  // Security check - clear environment variables!
	            local.pb.directory(arguments.workdir);
	            local.pb.redirectErrorStream(arguments.redirectErrorStream);

	            if ( arguments.logParams ) {
	            	instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Initiating executable: " & arguments.executable & " " & arguments.params & " in " & workdir);
	            } else {
	            	instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Initiating executable: " & arguments.executable & " [sensitive parameters obscured] in " & workdir);
	            }

	            local.outputBuffer = createObject("java", "java.lang.StringBuilder").init();
	            local.errorsBuffer = createObject("java", "java.lang.StringBuilder").init();
	            local.process = local.pb.start();
	            try {
	                if (!arguments.redirectErrorStream) {
	                	local.errorReader = createObject("component", "ReadThread").init(local.process.getErrorStream(), local.errorsBuffer);
	                	local.errorReader.run();
	                } else {
	                	local.errorReader = "";
	                }
	            	readStream( local.process.getInputStream(), local.outputBuffer );
	            	if (!isNull(local.errorReader)) {
	            		local.errorReader.join();
	            		if (!isNull(local.errorReader.exception)) {
	            			//throw local.errorReader.exception;
		            		throw(message=local.errorReader.exception.getMessage(), type=local.errorReader.exception.getType());
	            		}
	            	}
	            	local.process.waitFor();
	            } catch (Throwable e) {
	            	local.process.destroy();
	            	e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Exception thrown during execution of system command: " & e.getMessage(), e);
            		throw(message=e.getMessage(), type=e.getType());
	            }

	            local.output = local.outputBuffer.toString();
	            local.errors = local.errorsBuffer.toString();
	            local.exitValue = local.process.exitValue();
	            if ( !isNull(local.errors) && local.errors.length() > 0 ) {
	            	local.logErrors = local.errors;
	            	local.MAX_LEN = 256;
	            	if (local.logErrors.length() > local.MAX_LEN) {
	            		local.logErrors = local.logErrors.substring(0, local.MAX_LEN) & "(truncated at " & local.MAX_LEN & " characters)";
	            	}
	            	instance.logger.warning( javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Error during system command: " & local.logErrors );
	            }
	            if ( local.exitValue != 0 ) {
	            	instance.logger.warning( javaLoader().create("org.owasp.esapi.Logger").EVENT_FAILURE, "System command exited with non-zero status: " & local.exitValue );
	            }

	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, "System command complete");
	            return ExecuteResult.init(exitValue, local.output, local.errors);
	        } catch (IOException e) {
	            e = createObject("component", "cfesapi.org.owasp.esapi.errors.ExecutorException").init(instance.ESAPI, "Execution failure", "Exception thrown during execution of system command: " & e.getMessage(), e);
           		throw(message=e.getMessage(), type=e.getType());
	        }
    	</cfscript>
	</cffunction>


	<!---<cffunction access="private" returntype="void" name="readStream" output="false" hint="readStream reads lines from an input stream and returns all of them in a single string">
		<cfargument type="any" name="is" required="true" hint="java.io.InputStream: input stream to read from">
		<cfargument type="any" name="sb" required="true" hint="java.lang.StringBuilder: a string containing as many lines as the input stream contains, with newlines between lines">
		<cfscript>
		    local.isr = createObject("java", "java.io.InputStreamReader").init(arguments.is);
		    local.br = createObject("java", "java.io.BufferedReader").init(local.isr);
		    local.line = local.br.readLine();
		    while (!isNull(local.line)) {
		        arguments.sb.append(local.line).append('\n');
		        local.line = local.br.readLine();
		    }
    	</cfscript>
	</cffunction>--->


</cfcomponent>

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
		variables.executor = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.Executor" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.executor = newJava("org.owasp.esapi.ESAPI").executor();

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="executeSystemCommand" output="false"
	            hint="The reference implementation sets the work directory, escapes the parameters as per the Codec in use, and then executes the command without using concatenation. If there are failures, it will be logged. Privacy Note: Be careful if you pass PII to the executor, as the reference implementation logs the parameters. You MUST change this behavior if you are passing credit card numbers, TIN/SSN, or health information through this reference implementation, such as to a credit card or HL7 gateway.">
		<cfargument required="true" name="executable" hint="java.io.File"/>
		<cfargument required="true" name="params" hint="java.util.List"/>
		<cfargument required="true" name="workdir" hint="java.io.File"/>
		<cfargument required="true" name="codec" hint="org.owasp.esapi.codecs.Codec"/>

		<cfscript>
			try {
				if (this.ESAPI4JVERSION == 2) {
					return variables.executor.executeSystemCommand(arguments.executable, arguments.params, arguments.workdir, arguments.codec, false, false);
				}
				else {
					return variables.executor.executeSystemCommand(arguments.executable, arguments.params, arguments.workdir, arguments.codec);
				}
			}
			catch (org.owasp.esapi.errors.ExecutorException e) {
				throwException(createObject("component", "org.owasp.esapi.errors.ExecutorException").init(variables.ESAPI, e.getUserMessage(), e.getLogMessage(), e));
			}
		</cfscript>

	</cffunction>

</cfcomponent>
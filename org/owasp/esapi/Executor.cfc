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
<cfinterface hint="The Executor interface is used to run an OS command with reduced security risk. Implementations should do as much as possible to minimize the risk of injection into either the command or parameters. In addition, implementations should timeout after a specified time period in order to help prevent denial of service attacks. The class should perform logging and error handling as well. Finally, implementation should handle errors and generate an ExecutorException with all the necessary information. The reference implementation does all of the above.">

	<cffunction access="public" returntype="any" name="executeSystemCommand" output="false" hint="org.owasp.esapi.ExecuteResult: Executes a system command after checking that the executable exists and escaping all the parameters to ensure that injection is impossible. Implementations must change to the specified working directory before invoking the command.">
		<cfargument type="any" name="executable" required="true" hint="java.io.File: the command to execute">
		<cfargument type="Array" name="params" required="true" hint="the parameters of the command being executed">
		<cfargument type="any" name="workdir" required="false" hint="java.io.File: the working directory">
		<cfargument type="any" name="codec" required="false" hint="org.owasp.esapi.codecs.Codec: the codec to use to encode for the particular OS in use">
		<cfargument type="boolean" name="logParams" required="false" hint="use false if any parameters contains sensitive or confidential information">
		<cfargument type="boolean" name="redirectErrorStream" required="false" hint="">
	</cffunction>

</cfinterface>

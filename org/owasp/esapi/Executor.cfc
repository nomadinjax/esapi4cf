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
<cfinterface hint="The Executor interface is used to run an OS command with reduced security risk. Implementations should do as much as possible to minimize the risk of injection into either the command or parameters. In addition, implementations should timeout after a specified time period in order to help prevent denial of service attacks. The class should perform logging and error handling as well. Finally, implementation should handle errors and generate an ExecutorException with all the necessary information.">

	<cffunction access="public" returntype="String" name="executeSystemCommand" output="false"
	            hint="Executes a system command after checking that the executable exists and escaping all the parameters to ensure that injection is impossible. Implementations must change to the specified working directory before invoking the command.">
		<cfargument required="true" name="executable" hint="the command to execute"/>
		<cfargument required="true" name="params" hint="the parameters of the command being executed"/>
		<cfargument required="true" name="workdir" hint="the working directory"/>
		<cfargument required="true" name="codec" hint="the codec to use to encode for the particular OS in use"/>

	</cffunction>

</cfinterface>
<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfinterface hint="The LogFactory interface is intended to allow substitution of various logging packages, while providing a common interface to access them. In the reference implementation, JavaLogFactory.java implements this interface.  JavaLogFactory.java also contains an inner class called JavaLogger which implements Logger.java and uses the Java logging package to log events.">

	<cffunction access="public" returntype="org.owasp.esapi.Logger" name="getLogger" output="false"
	            hint="Gets the logger associated with the specified module name. The module name is used by the logger to log which module is generating the log events. The implementation of this method should return any preexisting Logger associated with this module name, rather than creating a new Logger. The JavaLogFactory reference implementation meets these requirements.">
		<cfargument required="true" type="String" name="moduleName" hint="The name of the module requesting the logger."/>

	</cffunction>

</cfinterface>
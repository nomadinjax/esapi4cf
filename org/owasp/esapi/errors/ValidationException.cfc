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
<cfcomponent displayname="ValidationException" extends="EnterpriseSecurityException" output="false" hint="A ValidationException should be thrown to indicate that the data provided by the user or from some other external source does not match the validation rules that have been specified for that data.">

	<cfscript>
		/** The UI reference that caused this ValidationException */
		instance.context = "";
	</cfscript>

	<cffunction access="public" returntype="ValidationException" name="init" output="false"
	            hint="Instantiates a new ValidationException.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="userMessage" hint="the message to display to users"/>
		<cfargument type="String" name="logMessage" hint="the message logged"/>
		<cfargument name="cause" hint="the cause"/>
		<cfargument type="String" name="context" hint="the source that caused this exception"/>

		<cfscript>
			if(structKeyExists(arguments, "cause")) {
				super.init(arguments.ESAPI, arguments.userMessage, arguments.logMessage, arguments.cause);
			}
			else if(structKeyExists(arguments, "userMessage") && structKeyExists(arguments, "logMessage")) {
				super.init(arguments.ESAPI, arguments.userMessage, arguments.logMessage);
			}
			else {
				super.init(arguments.ESAPI);
			}
			if(structKeyExists(arguments, "context")) {
				setContext(arguments.context);
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContext" output="false"
	            hint="Returns the UI reference that caused this ValidationException">

		<cfscript>
			return instance.context;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContext" output="false"
	            hint="Set's the UI reference that caused this ValidationException">
		<cfargument required="true" type="String" name="context" hint="the context to set, passed as a String"/>

		<cfscript>
			instance.context = arguments.context;
		</cfscript>

	</cffunction>

</cfcomponent>
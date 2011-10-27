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
<cfcomponent extends="StringValidationRule" output="false">

	<cfscript>
		/* OWASP AntiSamy markup verification policy */
		instance.antiSamyPolicy = "";

		instance.logger = "";
	</cfscript>
 
	<cffunction access="public" returntype="HTMLValidationRule" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="typeName" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="false">
		<cfargument type="String" name="whitelistPattern" required="false">
		<cfscript>
			super.init( argumentCollection=arguments );
			instance.logger = instance.ESAPI.getLogger( "HTMLValidationRule" );

	        local.resourceStream = "";
			try {
				local.resourceStream = instance.ESAPI.securityConfiguration().getResourceStream("antisamy-esapi.xml");
			} catch (java.io.IOException e) {
				throwError(newJava("org.apache.commons.configuration.ConfigurationRuntimeException").init("Couldn't find antisamy-esapi.xml", e));
			}
	        if (!isNull(local.resourceStream)) {
	        	try {
					instance.antiSamyPolicy = newJava("org.owasp.validator.html.Policy").getInstance(local.resourceStream);
				} catch (org.owasp.validator.html.PolicyException e) {
					throwError(newJava("org.apache.commons.configuration.ConfigurationRuntimeException").init("Couldn't parse antisamy policy", e));
				}
			}

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getValid" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				return super.getValid(argumentCollection=arguments);
			}

			return invokeAntiSamy( arguments.context, arguments.input );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="sanitize" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			local.safe = "";
			try {
				local.safe = invokeAntiSamy( arguments.context, arguments.input );
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				// just return safe
			}
			return local.safe;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="invokeAntiSamy" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			// CHECKME should this allow empty Strings? "   " us IsBlank instead?
		    if ( newJava("org.owasp.esapi.StringUtilities").isEmpty(arguments.input) ) {
				if (allowNull) {
					return "";
				}
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & " is required", logMessage="AntiSamy validation error: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ));
		    }

			local.canonical = super.getValid( arguments.context, arguments.input );

			try {
				local.as = newJava("org.owasp.validator.html.AntiSamy").init();
				local.test = local.as.scan(local.canonical, instance.antiSamyPolicy);

				local.errors = local.test.getErrorMessages();
				if ( !local.errors.isEmpty() ) {
					instance.logger.info( newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Cleaned up invalid HTML input: " & arrayToList(local.errors) );
				}

				return local.test.getCleanHTML().trim();

			} catch (org.owasp.validator.html.ScanException e) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input: context=" & arguments.context & " error=" & e.message, e, arguments.context ));
			} catch (org.owasp.validator.html.PolicyException e) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" & arguments.context & " error=" & e.message, e, arguments.context ));
			}
		</cfscript> 
	</cffunction>


</cfcomponent>

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
				throw new ConfigurationRuntimeException("Couldn't find antisamy-esapi.xml", e);
			}
	        if (!isNull(local.resourceStream)) {
	        	try {
					instance.antiSamyPolicy = javaLoader().create("org.owasp.validator.html.Policy").getInstance(local.resourceStream);
				} catch (PolicyException e) {
					throw new ConfigurationRuntimeException("Couldn't parse antisamy policy", e);
				}
			}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValid" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return invokeAntiSamy( arguments.context, arguments.input );
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="String" name="invokeAntiSamy" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			// CHECKME should this allow empty Strings? "   " us IsBlank instead?
		    if ( javaLoader().create("org.owasp.esapi.StringUtilities").isEmpty(arguments.input) ) {
				if (allowNull) {
					return "";
				}
				throw new ValidationException( arguments.context & " is required", "AntiSamy validation error: context=" & arguments.context & ", input=" & arguments.input, arguments.context );
		    }

			local.canonical = super.getValid( arguments.context, arguments.input );

			try {
				local.as = javaLoader().create("org.owasp.validator.html.AntiSamy").init();
				local.test = local.as.scan(local.canonical, instance.antiSamyPolicy);

				local.errors = local.test.getErrorMessages();
				if ( !local.errors.isEmpty() ) {
					instance.logger.info( javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Cleaned up invalid HTML input: " & arrayToList(local.errors) );
				}

				return local.test.getCleanHTML().trim();

			} catch (org.owasp.validator.html.ScanException e) {
				throw new ValidationException( arguments.context & ": Invalid HTML input", "Invalid HTML input: context=" & arguments.context & " error=" & e.getMessage(), e, arguments.context );
			} catch (org.owasp.validator.html.PolicyException e) {
				throw new ValidationException( arguments.context & ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" & arguments.context & " error=" & e.getMessage(), e, arguments.context );
			}
		</cfscript>
	</cffunction>


</cfcomponent>

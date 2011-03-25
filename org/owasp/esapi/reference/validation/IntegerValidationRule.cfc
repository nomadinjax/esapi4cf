<cfcomponent extends="BaseValidationRule" output="false" hint="A validator performs syntax and possibly semantic validation of a single piece of data from an untrusted source.">

	<cfscript>
		instance.minValue = createObject("java", "java.lang.Integer").MIN_VALUE;
		instance.maxValue = createObject("java", "java.lang.Integer").MAX_VALUE;
	</cfscript>

	<cffunction access="public" returntype="IntegerValidationRule" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="typeName" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="true">
		<cfargument type="numeric" name="minValue" required="false">
		<cfargument type="numeric" name="maxValue" required="false">
		<cfscript>
			super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );

			if (structKeyExists(arguments, "minValue")) {
				instance.minValue = arguments.minValue;
			}
			if (structKeyExists(arguments, "maxValue")) {
				instance.maxValue = arguments.maxValue;
			}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getValid" output="false" hint="numeric">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				return super.getValid(argumentCollection=arguments);
			}

			return safelyParse(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="safelyParse" output="false" hint="numeric">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			// do not allow empty Strings such as "   " - so trim to ensure isEmpty catches "    "
			if (!isNull(arguments.input)) arguments.input = arguments.input.trim();

		    if ( createObject("java", "org.owasp.esapi.StringUtilities").isEmpty(arguments.input) ) {
				if (instance.allowNull) {
					return "";
				}
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input number required", logMessage="Input number required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
		    }

		    // canonicalize
		    local.canonical = instance.encoder.canonicalize( arguments.input );

			if (instance.minValue > instance.maxValue) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid number input: context", logMessage="Validation parameter error for number: maxValue ( " & instance.maxValue & ") must be greater than minValue ( " & instance.minValue & ") for " & arguments.context, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}

			// validate min and max
			try {
				local.i = createObject("java", "java.lang.Integer").valueOf(local.canonical);
				if (local.i < instance.minValue) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage="Invalid number input must be between " & instance.minValue & " and " & instance.maxValue & ": context=" & arguments.context, logMessage="Invalid number input must be between " & instance.minValue & " and " & instance.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
					throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
				}
				if (local.i > instance.maxValue) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage="Invalid number input must be between " & minValue & " and " & instance.maxValue & ": context=" & arguments.context, logMessage="Invalid number input must be between " & instance.minValue & " and " & instance.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
					throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
				}
				return local.i;
			} catch (java.lang.NumberFormatException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( instance.ESAPI, arguments.context & ": Invalid number input", "Invalid number input format: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="sanitize" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			local.toReturn = createObject("java", "java.lang.Integer").valueOf( 0 );
			try {
				local.toReturn = safelyParse(arguments.context, arguments.input);
			} catch (cfesapi.org.owasp.esapi.errorsValidationException e ) {
				// do nothing
			}
			return local.toReturn;
		</cfscript>
	</cffunction>


</cfcomponent>

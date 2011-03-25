<cfcomponent extends="BaseValidationRule" output="false" hint="A validator performs syntax and possibly semantic validation of a single piece of data from an untrusted source.">

	<cfscript>
		instance.minValue = createObject("java", "java.lang.Double").NEGATIVE_INFINITY;
		instance.maxValue = createObject("java", "java.lang.Double").POSITIVE_INFINITY;
	</cfscript>

	<cffunction access="public" returntype="NumberValidationRule" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="typeName" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="true">
		<cfargument type="numeric" name="minValue" required="false">
		<cfargument type="numeric" name="maxValue" required="false">
		<cfscript>
			super.init(argumentCollection=arguments);

			instance.minValue = arguments.minValue;
			instance.maxValue = arguments.maxValue;

			// CHECKME fail fast?
	//		if (minValue > maxValue) {
	//			throw new IllegalArgumentException("Invalid number input: context Validation parameter error for number: maxValue ( " + maxValue + ") must be greater than minValue ( " + minValue + ")");
	//		}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getValid" output="false" hint="Returns Double or null">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				return super.getValid(argumentCollection=arguments);
			}

			try {
				return safelyParse(arguments.context, arguments.input);
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				throw(type=e.getType(), message=e.getMessage());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="sanitize" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			local.toReturn = createObject("java", "java.lang.Double").valueOf(0);
			try {
				local.toReturn = safelyParse(arguments.context, arguments.input);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// do nothing
			}
			return local.toReturn;
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="safelyParse" output="false" hint="Returns Double or null">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			// CHECKME should this allow empty Strings? "   " us IsBlank instead?
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

			local.d = "";
			// validate min and max
			try {
				local.d = createObject("java", "java.lang.Double").valueOf(createObject("java", "java.lang.Double").parseDouble( local.canonical ));
			} catch (java.lang.NumberFormatException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( instance.ESAPI, arguments.context & ": Invalid number input", "Invalid number input format: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}

			if (local.d.isInfinite()) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage="Invalid number input: context=" & arguments.context, logMessage="Invalid double input is infinite: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
			if (local.d.isNaN()) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage="Invalid number input: context=" & arguments.context, logMessage="Invalid double input is not a number: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
			if (local.d.doubleValue() < instance.minValue) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage="Invalid number input must be between " & instance.minValue & " and " & instance.maxValue & ": context=" & arguments.context, logMessage="Invalid number input must be between " & instance.minValue & " and " & instance.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
			if (local.d.doubleValue() > instance.maxValue) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage="Invalid number input must be between " & instance.minValue & " and " & instance.maxValue & ": context=" & arguments.context, logMessage="Invalid number input must be between " & instance.minValue & " and " & instance.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
			return local.d;
		</cfscript>
	</cffunction>


</cfcomponent>

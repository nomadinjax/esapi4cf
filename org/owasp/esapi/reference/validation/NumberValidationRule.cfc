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
<cfcomponent extends="BaseValidationRule" output="false" hint="A validator performs syntax and possibly semantic validation of a single piece of data from an untrusted source.">

	<cfscript>
		instance.minValue = createObject("java", "java.lang.Double").NEGATIVE_INFINITY;
		instance.maxValue = createObject("java", "java.lang.Double").POSITIVE_INFINITY;
		
		// These statics needed to detect double parsing DOS bug in Java
		instance.bigBad = "";
		instance.smallBad = "";
	
		one = createObject("java", "java.math.BigDecimal").init(1);
		two = createObject("java", "java.math.BigDecimal").init(2);
		
		tiny = one.divide(two.pow(1022));
		
		// 2^(-1022) ­ 2^(-1076)
		instance.bigBad = tiny.subtract(one.divide(two.pow(1076)));
		//2^(-1022) ­ 2^(-1075)
		instance.smallBad = tiny.subtract(one.divide(two.pow(1075)));
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
				throw(type=e.type, message=e.message);
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

		    //if MinValue is greater than maxValue then programmer is likely calling this wrong
			if (instance.minValue > instance.maxValue) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid number input: context", logMessage="Validation parameter error for number: maxValue ( " & instance.maxValue & ") must be greater than minValue ( " & instance.minValue & ") for " & arguments.context, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
			
			//convert to BigDecimal so we can safely parse dangerous numbers to 
			//check if the number may DOS the double parser
			local.bd = "";
			try {
				local.bd = createObject("java", "java.math.BigDecimal").init(local.canonical);
			} catch (Object e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( instance.ESAPI, arguments.context & ": Invalid number input", "Invalid number input format: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
			
			// Thanks to Brian Chess for this suggestion
			// Check if string input is in the "dangerous" double parsing range
			if (local.bd.compareTo(instance.smallBad) >= 0 && local.bd.compareTo(instance.bigBad) <= 0) {
				// if you get here you know you're looking at a bad value. The final
				// value for any double in this range is supposed to be the following safe #			
				return createObject("java", "java.lang.Double").init("2.2250738585072014E-308");
			}

			// the number is safe to parseDouble
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

<cfcomponent extends="BaseValidationRule" output="false">

	<cfscript>
		instance.maxCardLength = 19;

		/* Key used to pull out encoder in configuration.  Prefixed with "Validator." */
		static.CREDIT_CARD_VALIDATOR_KEY = "CreditCard";

		instance.ccrule = "";
	</cfscript>

	<cffunction access="public" returntype="CreditCardValidationRule" name="init" output="false" hint="Creates a CreditCardValidator using the rule found in security configuration">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="typeName" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="true">
		<cfargument type="StringValidationRule" name="validationRule" required="false">
		<cfscript>
			super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );
			if (structKeyExists(arguments, "validationRule")) {
				instance.ccrule = arguments.validationRule;
			}
			else {
				instance.ccrule = readDefaultCreditCardRule();
			}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="StringValidationRule" name="readDefaultCreditCardRule" output="false">
		<cfscript>
			local.p = instance.ESAPI.securityConfiguration().getValidationPattern( static.CREDIT_CARD_VALIDATOR_KEY );
			local.ccr = createObject("component", "StringValidationRule").init( instance.ESAPI, "ccrule", instance.encoder, local.p.pattern() );
			local.ccr.setMaximumLength(getMaxCardLength());
			local.ccr.setAllowNull( false );
			return local.ccr;
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

			try {
				// CHECKME should this allow empty Strings? "   " us IsBlank instead?
			    if ( javaLoader().create("org.owasp.esapi.StringUtilities").isEmpty(arguments.input) ) {
					if (allowNull) {
						return "";
					}
	       			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input credit card required", logMessage="Input credit card required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context);
					throw(message=cfex.getMessage(), type=cfex.getType());
			    }

			   	local.canonical = instance.ccrule.getValid( arguments.context, arguments.input );

				if( ! validCreditCardFormat(local.canonical)) {
	       			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid credit card input", logMessage="Invalid credit card input: context=" & arguments.context, context=arguments.context );
					throw(message=cfex.getMessage(), type=cfex.getType());
				}

				return local.canonical;
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				throw(message=e.getMessage(), type=e.getType());
			}
		</cfscript>
	</cffunction>


	<cffunction access="package" returntype="boolean" name="validCreditCardFormat" output="false" hint="Performs additional validation on the card nummber. This implementation performs Luhn algorithm checking">
		<cfargument type="String" name="ccNum" required="true" hint="number to be validated">
		<cfscript>
		    local.digitsOnly = createObject("java", "java.lang.StringBuilder").init();
			local.c = "";
			for (local.i = 0; local.i < arguments.ccNum.length(); local.i++) {
				local.c = arguments.ccNum.charAt(local.i);
				if (createObject("java", "java.lang.Character").isDigit(local.c)) {
					local.digitsOnly.append(local.c);
				}
			}

			local.sum = 0;
			local.digit = 0;
			local.addend = 0;
			local.timesTwo = false;

			for (local.i = local.digitsOnly.length() - 1; local.i >= 0; local.i--) {
				// guaranteed to be an int
				local.digit = createObject("java", "java.lang.Integer").valueOf(local.digitsOnly.substring(local.i, local.i + 1));
				if (local.timesTwo) {
					local.addend = local.digit * 2;
					if (local.addend > 9) {
						local.addend -= 9;
					}
				} else {
					local.addend = local.digit;
				}
				local.sum += local.addend;
				local.timesTwo = !local.timesTwo;
			}

			return local.sum % 10 == 0;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="sanitize" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return whitelist( arguments.input, javaLoader().create("org.owasp.esapi.EncoderConstants").CHAR_DIGITS );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setStringValidatorRule" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.reference.validation.StringValidationRule" name="ccrule" required="true" hint="the ccrule to set">
		<cfscript>
			instance.ccrule = arguments.ccrule;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="StringValidationRule" name="getStringValidatorRule" output="false">
		<cfscript>
			return instance.ccrule;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setMaxCardLength" output="false">
		<cfargument type="numeric" name="maxCardLength" required="true" hint="the maxCardLength to set">
		<cfscript>
			instance.maxCardLength = arguments.maxCardLength;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxCardLength" output="false">
		<cfscript>
			return instance.maxCardLength;
		</cfscript>
	</cffunction>


</cfcomponent>

<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.Validator" output="false">

	<cfscript>
		instance.ESAPI = "";

		/* A map of validation rules */
		instance.rules = {};

		/* The encoder to use for canonicalization */
		instance.encoder = "";

		/* The encoder to use for file system */
		instance.fileValidator = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Validator" name="init" output="false" hint="Default constructor uses the ESAPI standard encoder or construct a new DefaultValidator that will use the specified Encoder for canonicalization.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="false">
		<cfargument type="boolean" name="nested" required="false">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			if (structKeyExists(arguments, 'encoder')) {
				instance.encoder = arguments.encoder;
			}
			else {
	    		instance.encoder = instance.ESAPI.encoder();
			}

			// NOTE: ??? are we able to identify the caller to determine whether this is nested rather than passing a stupid argument ???
			if (!(structKeyExists(arguments, "nested") && arguments.nested)) {
				/* Initialize file validator with an appropriate set of codecs */
				local.list = [];
				local.list.add( "HTMLEntityCodec" );
				local.list.add( "PercentCodec" );
				local.fileEncoder = createObject("component", "DefaultEncoder").init( instance.ESAPI, local.list );
				instance.fileValidator = createObject("component", "DefaultValidator").init( instance.ESAPI, local.fileEncoder, true );
			}

	    	return this;
	    </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addRule" output="false" hint="Add a validation rule to the registry using the 'type name' of the rule as the key.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationRule" name="rule" required="true">
		<cfscript>
			instance.rules[arguments.rule.getTypeName()] = arguments.rule;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.ValidationRule" name="getRule" output="false" hint="Get a validation rule from the registry with the 'type name' of the rule as the key.">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			if (structKeyExists(instance.rules, arguments.name)) {
				return instance.rules[arguments.name];
			}
			return createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "");;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidInput" output="false" hint="Returns true if data received from browser is valid. Double encoding is treated as an attack. The default encoder supports html encoding, URL encoding, and javascript escaping. Input is canonicalized by default before validation.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="String" name="type" required="true">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="boolean" name="canonicalize" required="false" default="true">
		<cfscript>
			try {
				getValidInput( arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidInput" output="false" hint="Validates data received from the browser and returns a safe version. Only URL encoding is supported. Double encoding is treated as an attack.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name for the field to validate. This is used for error facing validation messages and element identification.">
		<cfargument type="String" name="input" required="true" hint="The actual user input data to validate.">
		<cfargument type="String" name="type" required="true" hint="The regular expression name which maps to the actual regular expression from 'ESAPI.properties'.">
		<cfargument type="numeric" name="maxLength" required="true" hint="The maximum String length allowed. If input is canonicalized per the canonicalize argument, then maxLength must be verified after canonicalization">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="boolean" name="canonicalize" required="false" default="true" hint="If canonicalize is true then input will be canonicalized before validation">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false" hint="If ValidationException is thrown, then add to error list instead of throwing out to caller">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidInput(arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return "";
			}

			local.rvr = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init( instance.ESAPI, arguments.type, instance.encoder );
			local.p = instance.ESAPI.securityConfiguration().getValidationPattern( arguments.type );
			if ( !isNull(local.p) ) {
				local.rvr.addWhitelistPattern( local.p );
			} else {
				local.rvr.addWhitelistPattern( arguments.type );
			}
			local.rvr.setMaximumLength(arguments.maxLength);
			local.rvr.setAllowNull(arguments.allowNull);
			local.rvr.setValidateInputAndCanonical(arguments.canonicalize);
			return local.rvr.getValid(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidDate" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="any" name="format" required="true" hint="java.text.DateFormat">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
		try {
			getValidDate( arguments.context, arguments.input, arguments.format, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			return false;
		}
		</cfscript>
	</cffunction>


	<cffunction acess="public" returntype="any" name="getValidDate" output="false" hint="Date">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="any" name="format" required="true" hint="java.text.DateFormat">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidDate(arguments.context, arguments.input, arguments.format, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return null
				return "";
			}

			local.dvr = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.DateValidationRule").init( instance.ESAPI, "SimpleDate", instance.encoder, arguments.format);
			local.dvr.setAllowNull(arguments.allowNull);
			return local.dvr.getValid(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidSafeHTML" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidSafeHTML( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidSafeHTML" output="false" hint="This implementation relies on the OWASP AntiSamy project.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidSafeHTML(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			local.hvr = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.HTMLValidationRule").init( instance.ESAPI, "safehtml", instance.encoder );
			local.hvr.setMaximumLength(arguments.maxLength);
			local.hvr.setAllowNull(arguments.allowNull);
			local.hvr.setValidateInputAndCanonical(false);
			return local.hvr.getValid(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidCreditCard" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidCreditCard( arguments.context, arguments.input, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidCreditCard" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidCreditCard(arguments.context, arguments.input, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			local.ccvr = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.CreditCardValidationRule").init( instance.ESAPI, "creditcard", instance.encoder );
			local.ccvr.setAllowNull(arguments.allowNull);
			return local.ccvr.getValid(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidDirectoryPath" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="any" name="parent" required="true" hint="java.io.File">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidDirectoryPath( arguments.context, arguments.input, arguments.parent, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidDirectoryPath" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="any" name="parent" required="true" hint="java.io.File">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidDirectoryPath(arguments.context, arguments.input, arguments.parent, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			try {
				if (isEmpty(arguments.input)) {
					if (arguments.allowNull) return "";
	       			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input directory path required", logMessage="Input directory path required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}

				local.dir = createObject("java", "java.io.File").init( arguments.input );

				// check dir exists and parent exists and dir is inside parent
				if ( !local.dir.exists() ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, does not exist: context=" & arguments.context & ", input=" & arguments.input );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}
				if ( !local.dir.isDirectory() ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not a directory: context=" & arguments.context & ", input=" & arguments.input );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}
				if ( !arguments.parent.exists() ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent does not exist: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}
				if ( !arguments.parent.isDirectory() ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent is not a directory: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}
				if ( !local.dir.getCanonicalPath().startsWith(arguments.parent.getCanonicalPath() ) ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not inside specified parent: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}

				// check canonical form matches input
				local.canonicalPath = local.dir.getCanonicalPath();
				local.canonical = instance.fileValidator.getValidInput( arguments.context, local.canonicalPath, "DirectoryName", 255, false);
				if ( !local.canonical.equals( arguments.input ) ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid directory name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}
				return local.canonical;
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Failure to validate directory path: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidFileName" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="Array" name="allowedExtensions" required="false" default="#instance.ESAPI.securityConfiguration().getAllowedFileExtensions()#">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidFileName( arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidFileName" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="Array" name="allowedExtensions" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidFileName(arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			if (arguments.allowedExtensions.isEmpty()) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Internal Error", "getValidFileName called with an empty or null list of allowed Extensions, therefore no files can be uploaded" );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			local.canonical = "";
			// detect path manipulation
			try {
				if (isEmpty(arguments.input)) {
					if (arguments.allowNull) return "";
		   			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input file name required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
		   			throw(type=cfex.getType(), message=cfex.getMessage());
				}

				// do basic validation
		        local.canonical = createObject("java", "java.io.File").init(arguments.input).getCanonicalFile().getName();
		        getValidInput( arguments.context, arguments.input, "FileName", 255, true );

				local.f = createObject("java", "java.io.File").init(local.canonical);
				local.c = local.f.getCanonicalPath();
				local.cpath = local.c.substring(local.c.lastIndexOf(createObject("java", "java.io.File").separator) + 1);

				// the path is valid if the input matches the canonical path
				if (arguments.input != local.cpath) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}

			} catch (java.io.IOException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid file name", "Invalid file name does not exist: context=" & arguments.context & ", canonical=" & local.canonical, e, arguments.context );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			// verify extensions
			local.i = arguments.allowedExtensions.iterator();
			while (local.i.hasNext()) {
				local.ext = local.i.next();
				if (arguments.input.toLowerCase().endsWith(local.ext.toLowerCase())) {
					return local.canonical;
				}
			}
			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file name does not have valid extension (" & arrayToList(arguments.allowedExtensions) & ")", logMessage="Invalid file name does not have valid extension (" & arrayToList(arguments.allowedExtensions) & "): context=" & arguments.context&", input=" & arguments.input, context=arguments.context );
			throw(type=cfex.getType(), message=cfex.getMessage());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidNumber" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidNumber" output="false" hint="numeric">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			local.minDoubleValue = createObject("java", "java.lang.Double").init(arguments.minValue);
			local.maxDoubleValue = createObject("java", "java.lang.Double").init(arguments.maxValue);
			return getValidDouble(arguments.context, arguments.input, local.minDoubleValue.doubleValue(), local.maxDoubleValue.doubleValue(), arguments.allowNull);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidDouble" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
	        try {
	            getValidDouble( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
	            return true;
	        } catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
	            return false;
	        }
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidDouble" output="false" hint="Returns Double or null">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return createObject("java", "java.lang.Double").init(createObject("java", "java.lang.Double").NaN);
			}

			local.nvr = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.NumberValidationRule").init( instance.ESAPI, "number", instance.encoder, arguments.minValue, arguments.maxValue );
			local.nvr.setAllowNull(arguments.allowNull);
			return local.nvr.getValid(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidInteger" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidInteger( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidInteger" output="false" hint="numeric">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return original input
				return "";
			}

			local.ivr = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.IntegerValidationRule").init( instance.ESAPI, "number", instance.encoder, arguments.minValue, arguments.maxValue );
			local.ivr.setAllowNull(arguments.allowNull);
			return local.ivr.getValid(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidFileContent" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="binary" name="input" required="true">
		<cfargument type="numeric" name="maxBytes" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidFileContent( arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="getValidFileContent" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="binary" name="input" required="true">
		<cfargument type="numeric" name="maxBytes" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidFileContent(arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// return empty byte array on error
				return createObject("java", "java.lang.String").init("").getBytes();
			}

			if (isEmpty(arguments.input)) {
				if (arguments.allowNull) return "";
	   			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			local.esapiMaxBytes = instance.ESAPI.securityConfiguration().getAllowedFileUploadSize();
			if (len(arguments.input) > local.esapiMaxBytes ) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & local.esapiMaxBytes & " bytes", logMessage="Exceeded ESAPI max length", context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}
			if (len(arguments.input) > arguments.maxBytes ) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & arguments.maxBytes & " bytes", logMessage="Exceeded maxBytes ( " & len(arguments.input) & ")", context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			return arguments.input;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidFileUpload" output="false" hint="Note: On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real path (/private/etc), not the symlink (/etc).">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="filepath" required="true">
		<cfargument type="String" name="filename" required="true">
		<cfargument type="any" name="parent" required="true" hint="java.io.File">
		<cfargument type="binary" name="content" required="true">
		<cfargument type="numeric" name="maxBytes" required="true">
		<cfargument type="boolean" name="allowNull" requird="true">
		<cfscript>
			return( isValidFileName( context=arguments.context, input=arguments.filename, allowNull=arguments.allowNull ) &&
					isValidDirectoryPath( arguments.context, arguments.filepath, arguments.parent, arguments.allowNull ) &&
					isValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull ) );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="assertValidFileUpload" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="filepath" required="true">
		<cfargument type="String" name="filename" required="true">
		<cfargument type="any" name="parent" required="true" hint="java.io.File">
		<cfargument type="binary" name="content" required="true">
		<cfargument type="numeric" name="maxBytes" required="true">
		<cfargument type="Array" name="allowedExtensions" required="true">
		<cfargument type="boolean" name="allowNull" requird="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			try {
				getValidFileName( arguments.context, arguments.filename, arguments.allowedExtensions, arguments.allowNull );
				getValidDirectoryPath( arguments.context, arguments.filepath, arguments.parent, arguments.allowNull );
				getValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull );
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidListItem" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="Array" name="list" required="true">
		<cfscript>
			try {
				getValidListItem( arguments.context, arguments.input, arguments.list);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidListItem" output="false" hint="Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. ">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="Array" name="list" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidListItem(arguments.context, arguments.input, arguments.list);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return original input
				return arguments.input;
			}

			if (arguments.list.contains(arguments.input)) return arguments.input;
			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid list item", logMessage="Invalid list item: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context );
			throw(type=cfex.getType(), message=cfex.getMessage());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidHTTPRequestParameterSet" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" requird="true">
		<cfargument type="Array" name="requiredNames" required="true">
		<cfargument type="Array" name="optionalNames" required="true">
		<cfscript>
			try {
				assertValidHTTPRequestParameterSet( arguments.context, arguments.request, arguments.requiredNames, arguments.optionalNames);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="assertValidHTTPRequestParameterSet" output="false" hint="Validates that the parameters in the current request contain all required parameters and only optional ones in addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="true">
		<cfargument type="Array" name="required" required="true">
		<cfargument type="Array" name="optional" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					assertValidHTTPRequestParameterSet(arguments.context, arguments.request, arguments.required, arguments.optional);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
			}

			local.actualNames = arguments.request.getParameterMap().keySet();

			// verify ALL required parameters are present
			local.missing = duplicate(arguments.required);
			local.missing.removeAll(local.actualNames);
			if (local.missing.size() > 0) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request missing parameters", logMessage="Invalid HTTP request missing parameters " & arrayToList(local.missing) & ": context=" & arguments.context, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			// verify ONLY optional + required parameters are present
			local.extra = duplicate(local.actualNames);
			local.extra.removeAll(arguments.required);
			local.extra.removeAll(arguments.optional);
			if (local.extra.size() > 0) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request extra parameters " & local.extra, logMessage="Invalid HTTP request extra parameters " & local.extra & ": context=" & arguments.context, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidPrintable" output="false" hint="Checks that all bytes are valid ASCII characters (between 33 and 126 inclusive). Passing input as an array does no decoding.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="any" name="input" required="true" hint="String or Array">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			try {
				getValidPrintable( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidPrintable" output="false" hint="Returns canonicalized and validated printable characters as a String or byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="any" name="input" required="true" hint="String or Array">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				try {
					return getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return original input
				return arguments.input;
			}

			if (isSimpleValue(arguments.input)) {
				try {
		    		local.canonical = instance.encoder.canonicalize(arguments.input);
		    		return createObject("java", "java.lang.String").init( getValidPrintable( arguments.context, local.canonical.toCharArray(), arguments.maxLength, arguments.allowNull) );
				    //TODO - changed this to base Exception since we no longer need EncodingException
			    	//TODO - this is a bit lame: we need to re-think this function.
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
			        cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid printable input", "Invalid encoding of printable input, context=" & arguments.context + ", input=" & arguments.input, e, arguments.context);
					throw(type=cfex.getType(), message=cfex.getMessage());
			    }
			}
			else if (isArray(arguments.input)) {
				if (isEmpty(arguments.input)) {
					if (arguments.allowNull) return "";
		   			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes required", logMessage="Input bytes required: HTTP request is null", context=arguments.context );
					throw(type=cfex.getType(), message=cfex.getMessage());
				}

				if (arrayLen(arguments.input) > arguments.maxLength) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes can not exceed " & arguments.maxLength & " bytes", logMessage="Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (arguments.input.length-arguments.maxLength) & " bytes: context=" & arguments.context & ", input=" & arrayToList(arguments.input, ""), context=arguments.context);
					throw(type=cfex.getType(), message=cfex.getMessage());
				}

				for (local.i = 1; local.i <= arrayLen(arguments.input); local.i++) {
					if (arguments.input[local.i] <= inputBaseN("20", 16) || arguments.input[local.i] >= inputBaseN("7E", 16) ) {
						cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input bytes: context=" & arguments.context, logMessage="Invalid non-ASCII input bytes, context=" & arguments.context & ", input=" & arrayToList(arguments.input, ""), context=arguments.context);
						throw(type=cfex.getType(), message=cfex.getMessage());
					}
				}
				return arguments.input;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidRedirectLocation" output="false" hint="Returns true if input is a valid redirect location.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfscript>
			return instance.ESAPI.validator().isValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidRedirectLocation" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			try {
				return instance.ESAPI.validator().getValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			// error has been added to list, so return original input
			return arguments.input;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="safeReadLine" output="false" hint="This implementation reads until a newline or the specified number of characters.">
		<cfargument type="any" name="in" required="true" hint="java.io.InputStream">
		<cfargument type="numeric" name="max" required="true">
		<cfscript>
			if (arguments.max <= 0) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI, "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream");
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			local.sb = createObject("java", "java.lang.StringBuilder").init();
			local.count = 0;

			try {
				while (true) {
					local.c = arguments.in.read();
					if ( local.c == -1 ) {
						if (local.sb.length() == 0) {
							return;
						}
						break;
					}
					if (local.c == 13 || local.c == 10) {
						break;
					}
					local.count++;
					if (local.count > arguments.max) {
						cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI, "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" & arguments.max & ")");
						throw(type=cfex.getType(), message=cfex.getMessage());
					}
					local.sb.append(chr(local.c));
				}
				return local.sb.toString();
			} catch (java.lang.IOException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI, "Invalid input", "Invalid readLine. Problem reading from input stream", e);
				throw(type=cfex.getType(), message=cfex.getMessage());
			}
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="boolean" name="isEmpty" output="false" hint="Helper function to check if a String/byte array/char array is empty">
		<cfargument type="any" name="input" required="true" hint="input value">
		<cfscript>
			if (isSimpleValue(arguments.input)) {
				return (arguments.input=="" || arguments.input.trim().length() == 0);
			}
			else if (isBinary(arguments.input)) {
				return (len(arguments.input) == 0);
			}
			else if (isArray(arguments.input)) {
				return (arrayLen(arguments.input) == 0);
			}
		</cfscript>
	</cffunction>


</cfcomponent>

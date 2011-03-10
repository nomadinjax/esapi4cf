<cfcomponent extends="BaseValidationRule" output="false">

	<cfscript>
		instance.format = createObject("java", "java.text.DateFormat").getDateInstance();
	</cfscript>

	<cffunction access="public" returntype="DateValidationRule" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="typeName" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="true">
		<cfargument type="any" name="newFormat" required="true" hint="java.text.DateFormat">
		<cfscript>
			super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );
			setDateFormat( arguments.newFormat );

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setDateFormat" output="false">
		<cfargument type="any" name="newFormat" required="true" hint="java.text.DateFormat">
		<cfscript>
	        if (isNull(arguments.newFormat)) {
				throw(object=createObject("java", "java.lang.IllegalArgumentException").init("DateValidationRule.setDateFormat requires a non-null DateFormat"));
			}

	        instance.format = arguments.newFormat;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Date" name="getValid" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return safelyParse(arguments.context, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="Date" name="safelyParse" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			// CHECKME should this allow empty Strings? "   " us IsBlank instead?
			if (javaLoader().create("org.owasp.esapi.StringUtilities").isEmpty(arguments.input)) {
				if (instance.allowNull) {
					return "";
				}
				cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.ValidationException').init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input date required", logMessage="Input date required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context);
				throw(message=cfex.getMessage(), type=cfex.getType());
			}

		    local.canonical = instance.encoder.canonicalize(arguments.input);

			try {
				return instance.format.parse(local.canonical);
			} catch (java.lang.Exception e) {
				cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.ValidationException').init(instance.ESAPI, arguments.context & ": Invalid date must follow the " & instance.format.getNumberFormat() & " format", "Invalid date: context=" & arguments.context & ", format=" & instance.format & ", input=" & arguments.input, e, arguments.context);
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
		</cfscript>
	</cffunction>


</cfcomponent>

<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";

		instance.rawBytes = "";
	</cfscript>

	<cffunction access="public" returntype="PlainText" name="init" output="false" hint="Construct a PlainText object from a String or binary.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="any" name="str" required="true" hint="The String that is converted to a UTF-8 encoded byte array to create the PlainText object.">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("PlainText");

			if (isBinary(arguments.str)) {
				// Must allow 0 length arrays though, to represent empty strings.
				assert(!isNull(arguments.str), "Byte array representing plaintext cannot be null.");
				// Make copy so mutable byte array str can't change PlainText.
				instance.rawBytes = duplicate(arguments.str);
			}
			else if (isSimpleValue(arguments.str)) {
				try {
				    assert(!isNull(arguments.str), "String for plaintext cannot be null.");
					instance.rawBytes = arguments.str.getBytes("UTF-8");
				} catch (UnsupportedEncodingException e) {
					// Should never happen.
					instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").EVENT_FAILURE, "PlainText(String) CTOR failed: Can't find UTF-8 byte-encoding!", e);
					throw(object=createObject("java.lang.RuntimeException").init("Can't find UTF-8 byte-encoding!", e));
				}
			}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="toString" output="false" hint="Convert the PlainText object to a UTF-8 encoded String.">
		<cfscript>
			try {
				return createObject("java", "java.lang.String").init(instance.rawBytes, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				// Should never happen.
				instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").EVENT_FAILURE, "PlainText.toString() failed: Can't find UTF-8 byte-encoding!", e);
				throw(object=createObject("java", "java.lang.RuntimeException").init("Can't find UTF-8 byte-encoding!", e));
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="asBytes" output="false" hint="Convert the PlainText object to a byte array.">
		<cfscript>
			return duplicate(instance.rawBytes);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="hashCode" output="false">
		<cfscript>
			return variables.toString().hashCode();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="overwrite" output="false">
		<cfscript>
			createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI).overwrite( instance.rawBytes );
		</cfscript>
	</cffunction>


</cfcomponent>

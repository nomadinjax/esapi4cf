<cfinterface>

	<cffunction access="public" returntype="void" name="addRule" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationRule" name="rule" required="true">
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.ValidationRule" name="getRule" output="false">
		<cfargument type="String" name="name" required="true">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidInput" output="false" hint="Calls isValidInput and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="String" name="type" required="true">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
		<cfargument type="boolean" name="canonicalize" required="false" default="true">
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidInput" output="false" hint="Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual user input data to validate.">
		<cfargument type="String" name="type" required="true" hint="The regular expression name that maps to the actual regular expression from 'ESAPI.properties'.">
		<cfargument type="numeric" name="maxLength" required="true" hint="The maximum post-canonicalized String length allowed.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="boolean" name="canonicalize" required="false" default="true" hint="If canonicalize is true then input will be canonicalized before validation">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidDate" output="false" hint="Calls isValidDate and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="any" name="format" required="true" hint="java.text.DateFormat">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction acess="public" returntype="any" name="getValidDate" output="false" hint="Date: Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual user input data to validate.">
		<cfargument type="any" name="format" required="true" hint="java.text.DateFormat: Required formatting of date inputted.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidSafeHTML" output="false" hint="Calls getValidSafeHTML and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidSafeHTML" output="false" hint="Returns canonicalized and validated 'safe' HTML that does not contain unwanted scripts in the body, attributes, CSS, URLs, or anywhere else. Implementors should reference the OWASP AntiSamy project for ideas on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual user input data to validate.">
		<cfargument type="numeric" name="maxLength" required="true" hint="The maximum String length allowed.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidCreditCard" output="false" hint="Calls getValidCreditCard and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidCreditCard" output="false" hint="Returns a canonicalized and validated credit card number as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual user input data to validate.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidDirectoryPath" output="false" hint="Calls getValidDirectoryPath and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="any" name="parent" required="true" hint="java.io.File">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidDirectoryPath" output="false" hint="Returns a canonicalized and validated directory path as a String, provided that the input maps to an existing directory that is an existing subdirectory (at any level) of the specified parent. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual input data to validate.">
		<cfargument type="any" name="parent" required="true" hint="java.io.File">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidFileName" output="false" hint="Calls getValidFileName and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="Array" name="allowedExtensions" required="false">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidFileName" output="false" hint="Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in 'ESAPI.properties'. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual input data to validate.">
		<cfargument type="Array" name="allowedExtensions" required="true">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidNumber" output="false" hint="Calls getValidNumber and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidNumber" output="false" hint="numeric: Returns a validated number as a double within the range of minValue to maxValue. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual input data to validate.">
		<cfargument type="numeric" name="minValue" required="true" hint="Lowest legal value for input.">
		<cfargument type="numeric" name="maxValue" required="true" hint="Highest legal value for input.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidInteger" output="false" hint="Calls getValidInteger and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="numeric" name="minValue" required="true">
		<cfargument type="numeric" name="maxValue" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidInteger" output="false" hint="numeric: Returns a validated integer. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual input data to validate.">
		<cfargument type="numeric" name="minValue" required="true" hint="Lowest legal value for input.">
		<cfargument type="numeric" name="maxValue" required="true" hint="Highest legal value for input.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>

	<!--- isValidDouble --->

	<cffunction access="public" returntype="any" name="getValidDouble" output="false" hint="Returns a validated real number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The actual input data to validate.">
		<cfargument type="numeric" name="minValue" required="true" hint="Lowest legal value for input.">
		<cfargument type="numeric" name="maxValue" required="true" hint="Highest legal value for input.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidFileContent" output="false" hint="Calls getValidFileContent and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="binary" name="input" required="true">
		<cfargument type="numeric" name="maxBytes" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="binary" name="getValidFileContent" output="false" hint="Returns validated file content as a byte array. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="binary" name="input" required="true" hint="The actual input data to validate.">
		<cfargument type="numeric" name="maxBytes" required="true" hint="The maximum number of bytes allowed in a legal file.">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidFileUpload" output="false" hint="Calls getValidFileUpload and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="directorypath" required="true">
		<cfargument type="String" name="filename" required="true">
		<cfargument type="any" name="parent" required="true" hint="java.io.File">
		<cfargument type="binary" name="content" required="true">
		<cfargument type="numeric" name="maxBytes" required="true">
		<cfargument type="boolean" name="allowNull" requird="true">
	</cffunction>

	<!--- assertValidFileUpload --->

	<cffunction access="public" returntype="boolean" name="isValidListItem" output="false" hint="Calls getValidListItem and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="Array" name="list" required="true">
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidListItem" output="false" hint="Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="String" name="input" required="true" hint="The value to search 'list' for.">
		<cfargument type="Array" name="list" required="true" hint="The list to search for 'input'.">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidHTTPRequestParameterSet" output="false" hint="Calls assertValidHTTPRequestParameterSet and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" requird="true">
		<cfargument type="Array" name="requiredNames" required="true">
		<cfargument type="Array" name="optionalNames" required="true">
	</cffunction>


	<cffunction access="public" returntype="void" name="assertValidHTTPRequestParameterSet" output="false" hint="Validates that the parameters in the current request contain all required parameters and only optional ones in addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="true">
		<cfargument type="Array" name="required" required="true" hint="parameters that are required to be in HTTP request">
		<cfargument type="Array" name="optional" required="true" hint="additional parameters that may be in HTTP request">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errors" required="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isValidPrintable" output="false" hint="Calls getValidPrintable and returns true if no exceptions are thrown.">
		<cfargument type="String" name="context" required="true">
		<cfargument type="any" name="input" required="true" hint="String or Array">
		<cfargument type="numeric" name="maxLength" required="true">
		<cfargument type="boolean" name="allowNull" required="true">
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidPrintable" output="false" hint="Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument type="String" name="context" required="true" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.">
		<cfargument type="any" name="input" required="true" hint="String or Array: data to be returned as valid and printable">
		<cfargument type="numeric" name="maxLength" required="true" hint="Maximum number of bytes stored in 'input'">
		<cfargument type="boolean" name="allowNull" required="true" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.">
		<cfargument type="ValidationErrorList" name="errors" required="false">
	</cffunction>

	<!--- isValidRedirectLocation --->
	<!--- getValidRedirectLocation --->

	<cffunction access="public" returntype="String" name="safeReadLine" output="false" hint="Reads from an input stream until end-of-line or a maximum number of characters. This method protects against the inherent denial of service attack in reading until the end of a line. If an attacker doesn't ever send a newline character, then a normal input stream reader will read until all memory is exhausted and the platform throws an OutOfMemoryError and probably terminates.">
		<cfargument type="any" name="in" required="true" hint="java.io.InputStream: The InputStream from which to read data">
		<cfargument type="numeric" name="max" required="true" hint="Maximum characters allowed to be read in per line">
	</cffunction>

</cfinterface>

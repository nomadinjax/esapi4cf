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
<cfinterface hint="The Validator interface defines a set of methods for canonicalizing and validating untrusted input. Implementors should feel free to extend this interface to accommodate their own data formats. Rather than throw exceptions, this interface returns boolean results because not all validation problems are security issues. Boolean returns allow developers to handle both valid and invalid results more cleanly than exceptions. Implementations must adopt a 'whitelist' approach to validation where a specific pattern or character set is matched. 'Blacklist' approaches that attempt to identify the invalid or disallowed characters are much more likely to allow a bypass with encoding or other tricks.">

	<cffunction access="public" returntype="boolean" name="isValidInput" output="false"
	            hint="Returns true if input is valid according to the specified type. The type parameter must be the name of a defined type in the ESAPI configuration or a valid regular expression. Implementers should take care to make the type storage simple to understand and configure.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="String" name="type" hint="The regular expression name that maps to the actual regular expression from 'ESAPI.properties'."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidInput" output="false"
	            hint="Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. When ValidationErrorList is specified, instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="String" name="type" hint="The regular expression name that maps to the actual regular expression from 'ESAPI.properties'."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDate" output="false"
	            hint="Returns true if input is a valid date according to the specified date format.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" name="format" hint="Required formatting of date inputted."/>
		<cfargument required="true" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" name="getValidDate" output="false"
	            hint="Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException and store it inside of the errorList argument, and input that is clearly an attack will generate a descriptive IntrusionException.  Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" name="format" hint="Required formatting of date inputted."/>
		<cfargument required="true" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidSafeHTML" output="false"
	            hint="Returns true if input is 'safe' HTML. Implementors should reference the OWASP AntiSamy project for ideas on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidSafeHTML" output="false"
	            hint="Returns canonicalized and validated 'safe' HTML. Implementors should reference the OWASP AntiSamy project for ideas on how to do HTML validation in a whitelist way, as this is an extremely difficult problem. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidCreditCard" output="false"
	            hint="Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidCreditCard" output="false"
	            hint="Returns a canonicalized and validated credit card number as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDirectoryPath" output="false"
	            hint="Returns true if input is a valid directory path.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidDirectoryPath" output="false"
	            hint="Returns a canonicalized and validated directory path as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileName" output="false"
	            hint="Returns true if input is a valid file name.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidFileName" output="false"
	            hint="Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in 'ESAPI.properties'.  Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidNumber" output="false"
	            hint="Returns true if input is a valid number within the range of minValue to maxValue.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" name="format" hint="Required formatting of number inputted."/>
		<cfargument required="true" type="numeric" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" type="numeric" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" name="getValidNumber" output="false"
	            hint="Returns a validated number as a double within the range of minValue to maxValue. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" name="format" hint="Required formatting of number inputted."/>
		<cfargument required="true" type="numeric" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" type="numeric" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidInteger" output="false"
	            hint="Returns true if input is a valid integer within the range of minValue to maxValue.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" type="numeric" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" name="getValidInteger" output="false"
	            hint="Returns a validated integer. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" type="numeric" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDouble" output="false"
	            hint="Returns true if input is a valid double within the range of minValue to maxValue.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" type="numeric" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" name="getValidDouble" output="false"
	            hint="Returns a validated real number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="minValue" hint="Lowest legal value for input."/>
		<cfargument required="true" type="numeric" name="maxValue" hint="Highest legal value for input."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileContent" output="false"
	            hint="Returns true if input is valid file content.  This is a good place to check for max file size, allowed character sets, and do virus scans.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="binary" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="maxBytes" hint="The maximum number of bytes allowed in a legal file."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="binary" name="getValidFileContent" output="false"
	            hint="Returns validated file content as a byte array. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="binary" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="numeric" name="maxBytes" hint="The maximum number of bytes allowed in a legal file."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileUpload" output="false"
	            hint="Returns true if a file upload has a valid name, path, and content.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="filepath" hint="The file path of the uploaded file."/>
		<cfargument required="true" type="String" name="filename" hint="The filename of the uploaded file"/>
		<cfargument required="true" type="binary" name="content" hint="A byte array containing the content of the uploaded file."/>
		<cfargument required="true" type="numeric" name="maxBytes" hint="The max number of bytes allowed for a legal file upload."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertValidFileUpload" output="false"
	            hint="Validates the filepath, filename, and content of a file. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="filepath" hint="The file path of the uploaded file."/>
		<cfargument required="true" type="String" name="filename" hint="The filename of the uploaded file"/>
		<cfargument required="true" type="binary" name="content" hint="A byte array containing the content of the uploaded file."/>
		<cfargument required="true" type="numeric" name="maxBytes" hint="The max number of bytes allowed for a legal file upload."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidHTTPRequest" output="false"
	            hint="Validate the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.">
		<cfargument name="httpRequest"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertIsValidHTTPRequest" output="false"
	            hint="Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument name="httpRequest"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidListItem" output="false"
	            hint="Returns true if input is a valid list item.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="Array" name="list" hint="The list to search for 'input'."/>

	</cffunction>

	<cffunction access="public" name="getValidListItem" output="false"
	            hint="Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="Array" name="list" hint="The list to search for 'input'."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidHTTPRequestParameterSet" output="false"
	            hint="Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="Array" name="requiredNames" hint="parameters that are required to be in HTTP request"/>
		<cfargument required="true" type="Array" name="optionalNames" hint="additional parameters that may be in HTTP request"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertIsValidHTTPRequestParameterSet" output="false"
	            hint="Validates that the parameters in the current request contain all required parameters and only optional ones in addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="Array" name="requiredNames" hint="parameters that are required to be in HTTP request"/>
		<cfargument required="true" type="Array" name="optionalNames" hint="additional parameters that may be in HTTP request"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidPrintable" output="false"
	            hint="Returns true if input contains only valid printable ASCII characters.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" name="input" hint="data to be checked for validity"/>
		<cfargument required="true" type="numeric" name="maxLength" hint="Maximum number of bytes stored in 'input'"/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" name="getValidPrintable" output="false" hint="Returns canonicalized and validated printable characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" name="input" hint="data to be checked for validity"/>
		<cfargument required="true" type="numeric" name="maxLength" hint="Maximum number of bytes stored in 'input'"/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidRedirectLocation" output="false"
	            hint="Returns true if input is a valid redirect location, as defined by 'ESAPI.properties'.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="redirect location to be checked for validity, according to rules set in 'ESAPI.properties'"/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidRedirectLocation" output="false"
	            hint="Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="input" hint="redirect location to be checked for validity, according to rules set in 'ESAPI.properties'"/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If validation is in error, resulting error will be stored in the errorList by context"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="safeReadLine" output="false"
	            hint="Reads from an input stream until end-of-line or a maximum number of characters. This method protects against the inherent denial of service attack in reading until the end of a line. If an attacker doesn't ever send a newline character, then a normal input stream reader will read until all memory is exhausted and the platform throws an OutOfMemoryError and probably terminates.">
		<cfargument required="true" name="inputStream" hint="The InputStream from which to read data"/>
		<cfargument required="true" type="numeric" name="maxLength" hint="Maximum characters allowed to be read in per line"/>

	</cffunction>

</cfinterface>
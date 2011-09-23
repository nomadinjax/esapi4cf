<!---

Declare ESAPI convenience function for persistence, i.e. ESAPI()

NOTES:
What about ColdSpring??
Is using just Application scope sufficient???

--->

<cffunction access="private" returntype="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" output="false" hint="Your one stop shop to access all things ESAPI. This function takes care of instantiating ESAPI the first time and persisting ESAPI for subsequent use.">
	<cfscript>
		if (!structKeyExists(application, "ESAPI") || !isInstanceOf(application.ESAPI, "cfesapi.org.owasp.esapi.ESAPI")) {
			lock scope="application" type="exclusive" timeout="1" {
				if (!structKeyExists(application, "ESAPI") || !isInstanceOf(application.ESAPI, "cfesapi.org.owasp.esapi.ESAPI")) {
					application.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
				}
			}
		}
		return application.ESAPI;
	</cfscript>
</cffunction>

<cfscript>
	/* Configure ESAPI */

	/* ensure every request sets the HTTP request and response objects */
	ESAPI().httpUtilities().setCurrentHTTP(getPageContext().getRequest(), getPageContext().getResponse());

	// is there anything we should always configure per request?
</cfscript>

<!--- ESAPI helper methods --->

<cffunction access="private" returntype="String" name="encodeForBase64" output="false" hint="Base64 encode a string. UTF-8 is used to encode the string and no line wrapping is performed.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return encodeForBase64Charset("UTF-8", arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForBase64Wrap" output="false" hint="Base64 encode a string with line wrapping. UTF-8 is used to encode the string and lines are wrapped at 64 characters..">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return encodeForBase64CharsetWrap("UTF-8", arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForBase64Charset" output="false" hint="Base64 encode a string after converting to bytes using the specified character set. No line wrapping is performed.">
	<cfargument type="String" name="charset" required="true" hint="The character set used to convert str to bytes.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForBase64(arguments.str.getBytes(arguments.charset), false);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForBase64CharsetWrap" output="false" hint="Base64 encode a string after converting to bytes using the specified character set and wrapping lines. Lines are wrapped at 64 characters.">
	<cfargument type="String" name="charset" required="true" hint="The character set used to convert str to bytes.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForBase64(arguments.str.getBytes(arguments.charset), true);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForCSS" output="false" hint="Encode string for use in CSS.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForCSS(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForHTML" output="false" hint="Encode string for use in HTML.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForHTML(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForHTMLAttribute" output="false" hint="Encode string for use in a HTML attribute.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForHTMLAttribute(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForJavaScript" output="false" hint="Encode string for use in JavaScript.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForJavaScript(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForURL" output="false" hint="Encode string for use in a URL.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForURL(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForVBScript" output="false" hint="Encode string for use in VBScript.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForVBScript(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForXML" output="false" hint="Encode string for use in XML.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForXML(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForXMLAttribute" output="false" hint="Encode string for use in a XML attribute.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForXMLAttribute(arguments.str);
	</cfscript>
</cffunction>


<cffunction access="private" returntype="String" name="encodeForXPath" output="false" hint="Encode string for use in XPath.">
	<cfargument type="String" name="str" required="true" hint="The string to encode.">
	<cfscript>
		return ESAPI().encoder().encodeForXPath(arguments.str);
	</cfscript>
</cffunction>

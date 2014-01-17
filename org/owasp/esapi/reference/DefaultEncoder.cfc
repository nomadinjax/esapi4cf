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
<cfcomponent implements="org.owasp.esapi.Encoder" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Encoder interface. This implementation takes a whitelist approach to encoding, meaning that everything not specifically identified in a list of 'immune' characters is encoded. Several methods follow the approach in the Microsoft AntiXSS Library. The Encoder performs two key functions The canonicalization algorithm is complex, as it has to be able to recognize encoded characters that might affect downstream interpreters without being told what encodings are possible. The stream is read one character at a time. If an encoded character is encountered, it is canonicalized and pushed back onto the stream. If the next character is encoded, then a intrusion exception is thrown for the double-encoding which is assumed to be an attack. The encoding methods also attempt to prevent double encoding, by canonicalizing strings that are passed to them for encoding. Currently the implementation supports: HTML Entity Encoding (including non-terminated), Percent Encoding, Backslash Encoding">

	<cfscript>
		variables.ESAPI = "";
		variables.encoder = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.Encoder" name="init" output="false"
	            hint="Instantiates a new DefaultEncoder">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="Array" name="codecs" hint="A list of codecs to use by the Encoder class"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;

			if(structKeyExists(arguments, "codecs")) {
				variables.encoder = createObject("java", "org.owasp.esapi.reference.DefaultEncoder").init(arguments.codecs);
			}
			else {
				variables.encoder = createObject("java", "org.owasp.esapi.ESAPI").encoder();
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="canonicalize" output="false">
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="false" type="boolean" name="strict" default="true"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			try {
				return variables.encoder.canonicalize(javaCast("string", arguments.input), javaCast("boolean", arguments.strict));
			}
			catch (org.owasp.esapi.errors.IntrusionException e) {
				// TODO: this does not seem flexible to handle various errors returned from Java
				throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getMessage("Encoder.canonicalize.badInput.userMessage"), e.getLogMessage()));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForHTML" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForHTML(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForHTMLAttribute" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForHTMLAttribute(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForCSS" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForCSS(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForJavaScript" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForJavaScript(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForVBScript" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForVBScript(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForSQL" output="false">
		<cfargument required="true" name="codec"/>
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForSQL(arguments.codec, javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForOS" output="false">
		<cfargument required="true" name="codec"/>
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForSQL(arguments.codec, javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForLDAP" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForLDAP(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForDN" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForDN(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForXPath" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForXPath(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForXML" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForXML(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForXMLAttribute" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForXMLAttribute(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForURL" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			try {
				return createObject("java", "java.net.URLEncoder").encode(javaCast("string", arguments.input), variables.ESAPI.securityConfiguration().getCharacterEncoding());
			}
			catch(java.io.UnsupportedEncodingException ex) {
				throwException(createObject("component", "org.owasp.esapi.errors.EncodingException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getMessage("Encoder.encodeForURL.typeMismatch.userMessage"), variables.ESAPI.resourceBundle().getMessage("Encoder.encodeForURL.typeMismatch.logMessage"), ex));
			}
			catch(java.lang.Exception e) {
				throwException(createObject("component", "org.owasp.esapi.errors.EncodingException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getMessage("Encoder.encodeForURL.badInput.userMessage"), variables.ESAPI.resourceBundle().getMessage("Encoder.encodeForURL.badInput.logMessage"), e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="decodeFromURL" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var canonical = "";
			if (isNull(arguments.input)) return "";
			canonical = this.canonicalize(arguments.input);
			try {
				return createObject("java", "java.net.URLDecoder").decode(canonical, variables.ESAPI.securityConfiguration().getCharacterEncoding());
			}
			catch(java.io.UnsupportedEncodingException ex) {
				throwException(createObject("component", "org.owasp.esapi.errors.EncodingException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getMessage("Encoder.decodeFromURL.typeMismatch.userMessage"), variables.ESAPI.resourceBundle().getMessage("Encoder.decodeFromURL.typeMismatch.logMessage"), ex));
			}
			catch(java.lang.Exception e) {
				throwException(createObject("component", "org.owasp.esapi.errors.EncodingException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getMessage("Encoder.decodeFromURL.badInput.userMessage"), variables.ESAPI.resourceBundle().getMessage("Encoder.decodeFromURL.badInput.logMessage"), e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForBase64" output="false">
		<cfargument required="true" type="binary" name="input"/>
		<cfargument required="true" type="boolean" name="wrap"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.encodeForBase64(arguments.input, javaCast("boolean", arguments.wrap));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="binary" name="decodeFromBase64" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if (isNull(arguments.input)) return "";
			return variables.encoder.decodeFromBase64(javaCast("string", arguments.input));
		</cfscript>

	</cffunction>

</cfcomponent>
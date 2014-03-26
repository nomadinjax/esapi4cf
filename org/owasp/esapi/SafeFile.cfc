<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="org.owasp.esapi.util.File" hint="Extension to java.io.File to prevent against null byte injections and other unforeseen problems resulting from unprintable characters causing problems in path lookups. This does _not_ prevent against directory traversal attacks.">

	<cfscript>
		// imports
		Utils = createObject("component", "org.owasp.esapi.util.Utils");

		variables.ESAPI = "";

		variables.PERCENTS_PAT = createObject("java", "java.util.regex.Pattern").compile("(%)([0-9a-fA-F])([0-9a-fA-F])");
		variables.FILE_BLACKLIST_PAT = createObject("java", "java.util.regex.Pattern").compile("([\\\\/:*?<>|])");
		variables.DIR_BLACKLIST_PAT = createObject("java", "java.util.regex.Pattern").compile("([*?<>|])");
	</cfscript>

	<cffunction access="public" returntype="SafeFile" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="path"/>
		<cfargument name="parent"/>
		<cfargument type="String" name="child"/>
		<cfargument name="uri"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;

			super.init(argumentCollection=arguments);
			doDirCheck(this.getParent());
			doFileCheck(this.getName());

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="doDirCheck" output="false">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var m1 = "";
			var m2 = "";
			var ch = "";
			var msgParams = [];

			m1 = variables.DIR_BLACKLIST_PAT.matcher(arguments.path);
			if(m1.find()) {
				msgParams = [arguments.path, m1.group()];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("SafeFile_doDirCheck_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("SafeFile_doDirCheck_illegalChar_userMessage", msgParams)));
			}

			m2 = variables.PERCENTS_PAT.matcher(arguments.path);
			if(m2.find()) {
				msgParams = [arguments.path, m2.group()];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("SafeFile_doDirCheck_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("SafeFile_doDirCheck_encodedChar_userMessage", msgParams)));
			}

			ch = containsUnprintableCharacters(arguments.path);
			if(ch != -1) {
				msgParams = [arguments.path, ch];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("SafeFile_doDirCheck_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("SafeFile_doDirCheck_unprintableChar_userMessage", msgParams)));
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="doFileCheck" output="false">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var m1 = "";
			var m2 = "";
			var ch = "";
			var msgParams = [];

			m1 = variables.FILE_BLACKLIST_PAT.matcher(arguments.path);
			if(m1.find()) {
				msgParams = [arguments.path, m1.group()];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("SafeFile_doFileCheck_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("SafeFile_doFileCheck_illegalChar_userMessage", msgParams)));
			}

			m2 = variables.PERCENTS_PAT.matcher(arguments.path);
			if(m2.find()) {
				msgParams = [arguments.path, m2.group()];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("SafeFile_doFileCheck_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("SafeFile_doFileCheck_encodedChar_userMessage", msgParams)));
			}

			ch = containsUnprintableCharacters(arguments.path);
			if(ch != -1) {
				msgParams = [arguments.path, ch];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("SafeFile_doFileCheck_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("SafeFile_doFileCheck_unprintableChar_userMessage", msgParams)));
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="numeric" name="containsUnprintableCharacters" output="false">
		<cfargument required="true" type="String" name="s"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var ch = "";

			for(i = 1; i <= len(arguments.s); i++) {
				ch = asc(mid(arguments.s, i, 1));
				if(ch < 32 || ch > 126) {
					return ch;
				}
			}
			return -1;
		</cfscript>

	</cffunction>

</cfcomponent>
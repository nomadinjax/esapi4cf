<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2008 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
--->
<cfcomponent extends="cfesapi.org.owasp.esapi.util.File" hint="Extension to java.io.File to prevent against null byte injections and other unforeseen problems resulting from unprintable characters causing problems in path lookups. This does _not_ prevent against directory traversal attacks.">

	<cfscript>
		instance.ESAPI = "";

		instance.PERCENTS_PAT = getJava("java.util.regex.Pattern").compile("(%)([0-9a-fA-F])([0-9a-fA-F])");
		instance.FILE_BLACKLIST_PAT = getJava("java.util.regex.Pattern").compile("([\\\\/:*?<>|])");
		instance.DIR_BLACKLIST_PAT = getJava("java.util.regex.Pattern").compile("([*?<>|])");
	</cfscript>

	<cffunction access="public" returntype="SafeFile" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="pathname">
		<cfargument name="parent">
		<cfargument type="String" name="child">
		<cfargument name="uri">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			super.init(argumentCollection=arguments);
			doDirCheck(this.getParent());
			doFileCheck(this.getName());

			return this;
		</cfscript>
	</cffunction>

	<cffunction access="private" returntype="void" name="doDirCheck" output="false">
		<cfargument required="true" type="String" name="path">
		<cfscript>
			var local = {};

			local.m1 = instance.DIR_BLACKLIST_PAT.matcher( arguments.path );
			if ( local.m1.find() ) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains illegal character: " & local.m1.group() ) );
			}

			local.m2 = instance.PERCENTS_PAT.matcher( arguments.path );
			if ( local.m2.find() ) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains encoded characters: " & local.m2.group() ) );
			}

			local.ch = containsUnprintableCharacters(arguments.path);
			if (local.ch != -1) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains unprintable character: " & local.ch) );
			}
		</cfscript>
	</cffunction>

	<cffunction access="private" returntype="void" name="doFileCheck" output="false">
		<cfargument required="true" type="String" name="path">
		<cfscript>
			var local = {};

			local.m1 = instance.FILE_BLACKLIST_PAT.matcher( arguments.path );
			if ( local.m1.find() ) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains illegal character: " & local.m1.group() ) );
			}

			local.m2 = instance.PERCENTS_PAT.matcher( arguments.path );
			if ( local.m2.find() ) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, "Invalid file", "File path (" & arguments.path & ") contains encoded characters: " & local.m2.group() ) );
			}

			local.ch = containsUnprintableCharacters(arguments.path);
			if (local.ch != -1) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, "Invalid file", "File path (" & arguments.path & ") contains unprintable character: " & local.ch) );
			}
		</cfscript>
	</cffunction>

	<cffunction access="private" returntype="numeric" name="containsUnprintableCharacters" output="false">
		<cfargument required="true" type="String" name="s">
		<cfscript>
			var local = {};

			for (local.i = 1; local.i <= len(arguments.s); local.i++) {
				local.ch = asc(mid(arguments.s, local.i, 1));
				if (local.ch < 32 || local.ch > 126) {
					return local.ch;
				}
			}
			return -1;
		</cfscript>
	</cffunction>

</cfcomponent>

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
<cfcomponent extends="org.owasp.esapi.util.File" hint="Extension to java.io.File to prevent against null byte injections and other unforeseen problems resulting from unprintable characters causing problems in path lookups. This does _not_ prevent against directory traversal attacks.">

	<cfscript>
		variables.ESAPI = "";
	
		variables.PERCENTS_PAT = newJava("java.util.regex.Pattern").compile("(%)([0-9a-fA-F])([0-9a-fA-F])");
		variables.FILE_BLACKLIST_PAT = newJava("java.util.regex.Pattern").compile("([\\\\/:*?<>|])");
		variables.DIR_BLACKLIST_PAT = newJava("java.util.regex.Pattern").compile("([*?<>|])");
	</cfscript>
	
	<cffunction access="public" returntype="SafeFile" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="pathname"/>
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
		
			m1 = variables.DIR_BLACKLIST_PAT.matcher(arguments.path);
			if(m1.find()) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains illegal character: " & m1.group()));
			}
		
			m2 = variables.PERCENTS_PAT.matcher(arguments.path);
			if(m2.find()) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains encoded characters: " & m2.group()));
			}
		
			ch = containsUnprintableCharacters(arguments.path);
			if(ch != -1) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains unprintable character: " & ch));
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
		
			m1 = variables.FILE_BLACKLIST_PAT.matcher(arguments.path);
			if(m1.find()) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains illegal character: " & m1.group()));
			}
		
			m2 = variables.PERCENTS_PAT.matcher(arguments.path);
			if(m2.find()) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, "Invalid file", "File path (" & arguments.path & ") contains encoded characters: " & m2.group()));
			}
		
			ch = containsUnprintableCharacters(arguments.path);
			if(ch != -1) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, "Invalid file", "File path (" & arguments.path & ") contains unprintable character: " & ch));
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
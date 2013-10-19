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
<cfcomponent extends="Object" output="false">

	<cfscript>
		variables.File = "";
	</cfscript>

	<cffunction access="public" returntype="File" name="init" output="false">
		<cfargument type="String" name="pathname"/>
		<cfargument name="parent"/>
		<cfargument type="String" name="child"/>
		<cfargument name="uri"/>

		<cfscript>
			if(structKeyExists(arguments, "pathname") && !cf8_isNull(arguments.pathname)) {
				variables.File = newJava("java.io.File").init(javaCast("string", arguments.pathname));
			}
			else if(structKeyExists(arguments, "parent") && !cf8_isNull(arguments.parent) && structKeyExists(arguments, "child") && !cf8_isNull(arguments.child)) {
				variables.File = newJava("java.io.File").init(arguments.parent, javaCast("string", arguments.child));
			}
			else if(structKeyExists(arguments, "uri") && !cf8_isNull(arguments.uri)) {
				variables.File = newJava("java.io.File").init(arguments.uri);
			}
			else {
				throwException(newJava("IOException").init("Invalid File Instantiation.", "You must provide either a pathname, a parent and child, or a uri."));
			}

			return this;
		</cfscript>

	</cffunction>

	<!---canRead()
	    canWrite()
	    compareTo(File pathname)
	    compareTo(Object o)
	    createNewFile()
	    createTempFile(String prefix, String suffix)
	    createTempFile(String prefix, String suffix, File directory)
	    delete()
	    deleteOnExit()
	    equals(Object obj)--->

	<cffunction access="public" returntype="boolean" name="exists" output="false">

		<cfscript>
			return variables.File.exists();
		</cfscript>

	</cffunction>

	<!---getAbsoluteFile()
	    getAbsolutePath()
	    getCanonicalFile()
	    getCanonicalPath()--->

	<cffunction access="public" returntype="String" name="getName" output="false">

		<cfscript>
			return variables.File.getName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getParent" output="false">

		<cfscript>
			return variables.File.getParent();
		</cfscript>

	</cffunction>

	<!---getParentFile() --->

	<cffunction access="public" returntype="String" name="getPath" output="false">

		<cfscript>
			return variables.File.getPath();
		</cfscript>

	</cffunction>

	<!--- hashCode()
	    isAbsolute()
	    isDirectory()
	    isFile()
	    isHidden()
	    lastModified()
	    length()
	    list()
	    list(FilenameFilter filter)
	    listFiles()
	    listFiles(FileFilter filter)
	    listFiles(FilenameFilter filter)
	    listRoots()
	    mkdir()
	    mkdirs()
	    renameTo(File dest)
	    setLastModified(long time)
	    setReadOnly()
	    toString()
	    toURI()
	    toURL()--->
</cfcomponent>
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
		<cfargument type="String" name="path"/>
		<cfargument name="parent"/>
		<cfargument type="String" name="child"/>
		<cfargument name="uri"/>

		<cfscript>
			if(structKeyExists(arguments, "path") && !isNull(arguments.path)) {
				variables.File = newJava("java.io.File").init(javaCast("string", arguments.path));
			}
			else if(structKeyExists(arguments, "parent") && !isNull(arguments.parent) && structKeyExists(arguments, "child") && !isNull(arguments.child)) {
				variables.File = newJava("java.io.File").init(arguments.parent, javaCast("string", arguments.child));
			}
			else if(structKeyExists(arguments, "uri") && !isNull(arguments.uri)) {
				variables.File = newJava("java.io.File").init(arguments.uri);
			}
			else {
				throwException(newJava("IOException").init("Invalid File Instantiation.", "You must provide either a path, a parent and child, or a uri."));
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="canRead" output="false">

		<cfscript>
			return variables.safeFile.canRead();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="canWrite" output="false">

		<cfscript>
			return variables.safeFile.canWrite();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="compareTo" output="false">
		<cfargument required="true" name="o">

		<cfscript>
			return variables.safeFile.compareTo(arguments.o);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="createNewFile" output="false">

		<cfscript>
			return variables.safeFile.createNewFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="createTempFile" output="false">
		<cfargument required="true" type="String" name="prefix">
		<cfargument required="true" type="String" name="suffix">
		<cfargument type="String" name="directory">

		<cfscript>
			if (structKeyExists(arguments, "directory")) {
				return variables.safeFile.createTempFile(javaCast("string", arguments.prefix), javaCast("string", arguments.suffix), arguments.directory);
			}
			else {
				return variables.safeFile.createTempFile(javaCast("string", arguments.prefix), javaCast("string", arguments.suffix));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="delete" output="false">

		<cfscript>
			return variables.safeFile.delete();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="deleteOnExit" output="false">

		<cfscript>
			return variables.safeFile.deleteOnExit();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isEquals" output="false">
		<cfargument required="true" name="obj">

		<cfscript>
			return variables.safeFile.equals(obj);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="exists" output="false">

		<cfscript>
			return variables.File.exists();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getAbsoluteFile" output="false">

		<cfscript>
			return variables.safeFile.getAbsoluteFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAbsolutePath" output="false">

		<cfscript>
			return variables.safeFile.getAbsolutePath();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getCanonicalFile" output="false">

		<cfscript>
			return variables.safeFile.getCanonicalFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCanonicalPath" output="false">

		<cfscript>
			return variables.safeFile.getCanonicalPath();
		</cfscript>

	</cffunction>

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

	<cffunction access="public" name="getParentFile" output="false">

		<cfscript>
			return variables.safeFile.getParentFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPath" output="false">

		<cfscript>
			return variables.File.getPath();
		</cfscript>

	</cffunction>

	<!--- FIXME: CF8 conflict
	<cffunction access="public" returntype="numeric" name="hashCode" output="false">

		<cfscript>
			return variables.safeFile.hashCode();
		</cfscript>

	</cffunction> --->

	<cffunction access="public" returntype="boolean" name="isAbsolute" output="false">

		<cfscript>
			return variables.safeFile.isAbsolute();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isDirectory" output="false">

		<cfscript>
			return variables.safeFile.isDirectory();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isFile" output="false">

		<cfscript>
			return variables.safeFile.isFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="isHidden" output="false">

		<cfscript>
			return variables.safeFile.isHidden();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="lastModified" output="false">

		<cfscript>
			return variables.safeFile.lastModified();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="length" output="false">

		<cfscript>
			return variables.safeFile.length();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="list" output="false">
		<cfargument name="filter">

		<cfscript>
			if (structKeyExists(arguments, "filter")) {
				return variables.safeFile.list(arguments.filter);
			}
			else {
				return variables.safeFile.list();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="listFiles" output="false">
		<cfargument name="filter">

		<cfscript>
			if (structKeyExists(arguments, "filter")) {
				return variables.safeFile.listFiles(arguments.filter);
			}
			else {
				return variables.safeFile.listFiles();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="listRoots" output="false">

		<cfscript>
			return variables.safeFile.listRoots();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="mkdir" output="false">

		<cfscript>
			return variables.safeFile.mkdir();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="mkdirs" output="false">

		<cfscript>
			return variables.safeFile.mkdirs();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="renameTo" output="false">
		<cfargument required="true" name="dest">

		<cfscript>
			return variables.safeFile.renameTo(arguments.dest);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="setLastModified" output="false">
		<cfargument required="true" type="Date" name="time">

		<cfscript>
			return variables.safeFile.setLastModified(javaCast("long", arguments.time.getTime()));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="setReadOnly" output="false">

		<cfscript>
			return variables.safeFile.setReadOnly();
		</cfscript>

	</cffunction>

	<!--- FIXME: CF8 conflict
	<cffunction access="public" returntype="String" name="toString" output="false">

		<cfscript>
			return variables.safeFile.toString();
		</cfscript>

	</cffunction> --->

	<cffunction access="public" name="toURI" output="false">

		<cfscript>
			return variables.safeFile.toURI();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="toURL" output="false">

		<cfscript>
			return variables.safeFile.toURL();
		</cfscript>

	</cffunction>

</cfcomponent>
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
				variables.File = createObject("java", "java.io.File").init(javaCast("string", arguments.path));
			}
			else if(structKeyExists(arguments, "parent") && !isNull(arguments.parent) && structKeyExists(arguments, "child") && !isNull(arguments.child)) {
				variables.File = createObject("java", "java.io.File").init(arguments.parent, javaCast("string", arguments.child));
			}
			else if(structKeyExists(arguments, "uri") && !isNull(arguments.uri)) {
				variables.File = createObject("java", "java.io.File").init(arguments.uri);
			}
			else {
				throwException(createObject("java", "IOException").init("Invalid File Instantiation.", "You must provide either a path, a parent and child, or a uri."));
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="canRead" output="false">

		<cfscript>
			return variables.File.canRead();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="canWrite" output="false">

		<cfscript>
			return variables.File.canWrite();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="compareTo" output="false">
		<cfargument required="true" name="o">

		<cfscript>
			return variables.File.compareTo(arguments.o);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="createNewFile" output="false">

		<cfscript>
			return variables.File.createNewFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="createTempFile" output="false">
		<cfargument required="true" type="String" name="prefix">
		<cfargument required="true" type="String" name="suffix">
		<cfargument type="String" name="directory">

		<cfscript>
			if (structKeyExists(arguments, "directory")) {
				return variables.File.createTempFile(javaCast("string", arguments.prefix), javaCast("string", arguments.suffix), arguments.directory);
			}
			else {
				return variables.File.createTempFile(javaCast("string", arguments.prefix), javaCast("string", arguments.suffix));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="delete" output="false">

		<cfscript>
			return variables.File.delete();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="deleteOnExit" output="false">

		<cfscript>
			return variables.File.deleteOnExit();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isEquals" output="false">
		<cfargument required="true" name="obj">

		<cfscript>
			return variables.File.equals(obj);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="exists" output="false">

		<cfscript>
			return variables.File.exists();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getAbsoluteFile" output="false">

		<cfscript>
			return variables.File.getAbsoluteFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAbsolutePath" output="false">

		<cfscript>
			return variables.File.getAbsolutePath();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getCanonicalFile" output="false">

		<cfscript>
			return variables.File.getCanonicalFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCanonicalPath" output="false">

		<cfscript>
			return variables.File.getCanonicalPath();
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
			return variables.File.getParentFile();
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
			return variables.File.hashCode();
		</cfscript>

	</cffunction> --->

	<cffunction access="public" returntype="boolean" name="isAbsolute" output="false">

		<cfscript>
			return variables.File.isAbsolute();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isDirectory" output="false">

		<cfscript>
			return variables.File.isDirectory();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isFile" output="false">

		<cfscript>
			return variables.File.isFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="isHidden" output="false">

		<cfscript>
			return variables.File.isHidden();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="lastModified" output="false">

		<cfscript>
			return variables.File.lastModified();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="length" output="false">

		<cfscript>
			return variables.File.length();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="list" output="false">
		<cfargument name="filter">

		<cfscript>
			if (structKeyExists(arguments, "filter")) {
				return variables.File.list(arguments.filter);
			}
			else {
				return variables.File.list();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="listFiles" output="false">
		<cfargument name="filter">

		<cfscript>
			if (structKeyExists(arguments, "filter")) {
				return variables.File.listFiles(arguments.filter);
			}
			else {
				return variables.File.listFiles();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="listRoots" output="false">

		<cfscript>
			return variables.File.listRoots();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="mkdir" output="false">

		<cfscript>
			return variables.File.mkdir();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="mkdirs" output="false">

		<cfscript>
			return variables.File.mkdirs();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="renameTo" output="false">
		<cfargument required="true" name="dest">

		<cfscript>
			return variables.File.renameTo(arguments.dest);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="setLastModified" output="false">
		<cfargument required="true" type="Date" name="time">

		<cfscript>
			return variables.File.setLastModified(javaCast("long", arguments.time.getTime()));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="setReadOnly" output="false">

		<cfscript>
			return variables.File.setReadOnly();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringData" output="false">

		<cfscript>
			return variables.File.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="toURI" output="false">

		<cfscript>
			return variables.File.toURI();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="toURL" output="false">

		<cfscript>
			return variables.File.toURL();
		</cfscript>

	</cffunction>

</cfcomponent>
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
<cfcomponent extends="org.owasp.esapi.util.Object" hint="Extension to java.io.File to prevent against null byte injections and other unforeseen problems resulting from unprintable characters causing problems in path lookups. This does _not_ prevent against directory traversal attacks.">

	<cfscript>
		variables.ESAPI = "";
		variables.safeFile = "";
	</cfscript>

	<cffunction access="public" returntype="SafeFile" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="path"/>
		<cfargument name="parent"/>
		<cfargument type="String" name="child"/>
		<cfargument name="uri"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;

			if (structKeyExists(arguments, "parent") && !isNull(arguments.parent) && structKeyExists(arguments, "child") && !isNull(arguments.child)) {
				if (isInstanceOf(arguments.parent, "java.io.File") ) {
					try {
						variables.safeFile = newJava("org.owasp.esapi.SafeFile").init(arguments.parent, javaCast("string", arguments.child));
					}
					catch (org.owasp.esapi.errors.ValidationException e) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, e.getUserMessage(), e.getLogMessage()));
					}
				}
				else {
					try {
						variables.safeFile = newJava("org.owasp.esapi.SafeFile").init(javaCast("string", arguments.parent), javaCast("string", arguments.child));
					}
					catch (org.owasp.esapi.errors.ValidationException e) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, e.getUserMessage(), e.getLogMessage()));
					}
				}
			}
			else if (structKeyExists(arguments, "path") && !isNull(arguments.path)) {
				try {
					variables.safeFile = newJava("org.owasp.esapi.SafeFile").init(javaCast("string", arguments.path));
				}
				catch (org.owasp.esapi.errors.ValidationException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, e.getUserMessage(), e.getLogMessage()));
				}
			}
			else if (structKeyExists(arguments, "uri") && !isNull(arguments.uri)) {
				try {
					variables.safeFile = newJava("org.owasp.esapi.SafeFile").init(arguments.uri);
				}
				catch (org.owasp.esapi.errors.ValidationException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, e.getUserMessage(), e.getLogMessage()));
				}
			}
			else {
				throw(object=newJava("java.io.IOException").init("Invalid File Instantiation. You must provide either a pathname, a parent and child, or a uri."));
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
			return variables.safeFile.exists();
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
			return variables.safeFile.getName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getParent" output="false">

		<cfscript>
			return variables.safeFile.getParent();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getParentFile" output="false">

		<cfscript>
			return variables.safeFile.getParentFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPath" output="false">

		<cfscript>
			return variables.safeFile.getPath();
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
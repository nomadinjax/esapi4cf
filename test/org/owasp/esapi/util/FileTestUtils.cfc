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
<cfcomponent extends="org.owasp.esapi.util.Object" output="false" hint="Utilities to help with tests that involve files or directories.">

	<cfscript>
		System = createObject("java", "java.lang.System");

		variables.CLASS = getMetaData(this);
		variables.CLASS_NAME = listLast(variables.CLASS.name, ".");
		variables.DEFAULT_PREFIX = variables.CLASS_NAME & '.';
		variables.DEFAULT_SUFFIX = ".tmp";
		variables.rand = "";
		/*
		    Rational for switching from SecureRandom to Random:

		    This is used for generating filenames for temporary
		    directories. Origionally this was using SecureRandom for
		    this to make /tmp races harder. This is not necessary as
		    mkdir always returns false if if the directory already
		    exists.

		    Additionally, SecureRandom for some reason on linux
		    is appears to be reading from /dev/random instead of
		    /dev/urandom. As such, the many calls for temporary
		    directories in the unit tests quickly depleates the
		    entropy pool causing unit test runs to block until more
		    entropy is collected (this is why moving the mouse speeds
		    up unit tests).
		*/
		variables.secRand = newJava("java.security.SecureRandom").init();
		variables.rand = newJava("java.util.Random").init(variables.secRand.nextLong());
	</cfscript>

	<cffunction access="public" returntype="String" name="toHexString" output="false"
	            hint="Convert a long to it's hex representation. Unlike Long##toHexString(long) this always returns 16 digits.">
		<cfargument required="true" type="numeric" name="l" hint="The long to convert."/>

		<cfscript>
			// CF8 requires 'var' at the top
			var initial = "";
			var sb = "";

			initial = newJava("java.lang.Long").toHexString(arguments.l);
			if(initial.length() == 16)
				return initial;
			sb = newJava("java.lang.StringBuffer").init(16);
			sb.append(initial);
			while(sb.length() < 16)
				sb.insert(0, '0');
			return sb.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="createTmpDirectory" output="false" hint="Create a temporary directory.">
		<cfargument name="parent" hint="The parent directory for the temporary directory. If this is null, the system property 'java.io.tmpdir' is used."/>
		<cfargument type="String" name="prefix" hint="The prefix for the directory's name. If this is null, the full class name of this class is used."/>
		<cfargument type="String" name="suffix" hint="The suffix for the directory's name. If this is null, '.tmp' is used."/>

		<cfscript>
			// CF8 requires 'var' at the top
			var name = "";
			var dir = "";

			if(!structKeyExists(arguments, "prefix") || isNull(arguments.prefix))
				arguments.prefix = variables.DEFAULT_PREFIX;
			else if(!arguments.prefix.endsWith("."))
				arguments.prefix &= '.';
			if(!structKeyExists(arguments, "suffix") || isNull(arguments.suffix))
				arguments.suffix = variables.DEFAULT_SUFFIX;
			else if(!arguments.suffix.startsWith("."))
				arguments.suffix = "." & arguments.suffix;
			if(!structKeyExists(arguments, "parent") || isNull(arguments.parent))
				arguments.parent = newJava("java.io.File").init(System.getProperty("java.io.tmpdir"));
			name = arguments.prefix & toHexString(variables.rand.nextLong()) & arguments.suffix;
			dir = newJava("java.io.File").init(arguments.parent, name);
			if(!dir.mkdir())
				throw(object=newJava("java.io.IOException").init("Unable to create temporary directory " & dir));
			return dir.getCanonicalFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isChildSubDirectory" output="false"
	            hint="Checks that child is a directory and really a child of parent. This verifies that the {@link File##getCanonicalFile() canonical} child is actually a child of parent. This should fail if the child is a symbolic link to another directory and therefore should not be traversed in a recursive traversal of a directory.">
		<cfargument required="true" name="parent" hint="The supposed parent of the child"/>
		<cfargument required="true" name="child" hint="The child to check"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var childsParent = "";

			if(!isObject(arguments.child))
				throw(object=newJava("java.lang.NullPointerException").init("child argument is null"));
			if(!arguments.child.isDirectory())
				return false;
			if(!isObject(arguments.parent))
				throw(object=newJava("java.lang.NullPointerException").init("parent argument is null"));
			arguments.parent = arguments.parent.getCanonicalFile();
			arguments.child = arguments.child.getCanonicalFile();
			childsParent = arguments.child.getParentFile();
			if(childsParent == "")
				return false;// sym link to /?
			childsParent = childsParent.getCanonicalFile();// just in case...
			if(!arguments.parent.equals(childsParent))
				return false;
			return true;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="delete" output="false"
	            hint="Delete a file. Unlinke {@link File##delete()}, this throws an exception if deletion fails.">
		<cfargument required="true" name="file" hint="The file to delete"/>

		<cfscript>
			if(!isObject(arguments.file) || !arguments.file.exists())
				return;
			if(!arguments.file.delete())
				throw(object=newJava("java.io.IOException").init("Unable to delete file " & arguments.file.getAbsolutePath()));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="deleteRecursively" output="false"
	            hint="Recursively delete a file. If file is a directory, subdirectories and files are also deleted. Care is taken to not traverse symbolic links in this process. A null file or a file that does not exist is considered to already been deleted.">
		<cfargument required="true" name="file" hint="The file or directory to be deleted"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var children = "";
			var child = "";

			if(!isObject(arguments.file) || !arguments.file.exists())
				return;// already deleted?
			if(arguments.file.isDirectory()) {
				children = arguments.file.listFiles();
				for(i = 1; i <= arrayLen(children); i++) {
					child = children[i];
					if(isChildSubDirectory(arguments.file, child))
						deleteRecursively(child);
					else
						delete(child);
				}
			}

			// finally
			delete(arguments.file);
		</cfscript>

	</cffunction>

</cfcomponent>
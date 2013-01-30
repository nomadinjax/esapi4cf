<cfcomponent extends="esapi4cf.org.owasp.esapi.util.Object" output="false" hint="Utilities to help with tests that involve files or directories.">
	<!---
	import java.io.File;
	import java.io.IOException;
	import java.security.SecureRandom;
	import java.util.Random;
	--->

	<cfscript>
		instance.CLASS = getMetaData( this );
		instance.CLASS_NAME = listLast( instance.CLASS.name, "." );
		instance.DEFAULT_PREFIX = instance.CLASS_NAME & '.';
		instance.DEFAULT_SUFFIX = ".tmp";
		instance.rand = "";
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
		instance.secRand = getJava( "java.security.SecureRandom" ).init();
		instance.rand = getJava( "java.util.Random" ).init( instance.secRand.nextLong() );
	</cfscript>

	<cffunction access="public" returntype="String" name="toHexString" output="false"
	            hint="Convert a long to it's hex representation. Unlike Long##toHexString(long) this always returns 16 digits.">
		<cfargument required="true" type="numeric" name="l" hint="The long to convert."/>

		<cfscript>
			var local = {};
			local.initial = "";
			local.sb = "";

			local.initial = getJava( "java.lang.Long" ).toHexString( arguments.l );
			if(local.initial.length() == 16)
				return local.initial;
			local.sb = getJava( "java.lang.StringBuffer" ).init( 16 );
			local.sb.append( local.initial );
			while(local.sb.length() < 16)
				local.sb.insert( 0, '0' );
			return local.sb.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="createTmpDirectory" output="false"
	            hint="Create a temporary directory.">
		<cfargument name="parent" hint="The parent directory for the temporary directory. If this is null, the system property 'java.io.tmpdir' is used."/>
		<cfargument type="String" name="prefix" hint="The prefix for the directory's name. If this is null, the full class name of this class is used."/>
		<cfargument type="String" name="suffix" hint="The suffix for the directory's name. If this is null, '.tmp' is used."/>

		<cfscript>
			var local = {};
			local.name = "";
			local.dir = "";

			if(!structKeyExists( arguments, "prefix" ))
				arguments.prefix = instance.DEFAULT_PREFIX;
			else if(!arguments.prefix.endsWith( "." ))
				arguments.prefix &= '.';
			if(!structKeyExists( arguments, "suffix"))
				arguments.suffix = instance.DEFAULT_SUFFIX;
			else if(!arguments.suffix.startsWith( "." ))
				arguments.suffix = "." & arguments.suffix;
			if(!structKeyExists( arguments, "parent"))
				arguments.parent = getJava( "java.io.File" ).init( System.getProperty( "java.io.tmpdir" ) );
			local.name = arguments.prefix & toHexString( instance.rand.nextLong() ) & arguments.suffix;
			local.dir = getJava( "java.io.File" ).init( arguments.parent, local.name );
			if(!local.dir.mkdir())
				throwException( getJava( "java.io.IOException" ).init( "Unable to create temporary directory " & local.dir ) );
			return local.dir.getCanonicalFile();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isChildSubDirectory" output="false"
	            hint="Checks that child is a directory and really a child of parent. This verifies that the {@link File##getCanonicalFile() canonical} child is actually a child of parent. This should fail if the child is a symbolic link to another directory and therefore should not be traversed in a recursive traversal of a directory.">
		<cfargument required="true" name="parent" hint="The supposed parent of the child"/>
		<cfargument required="true" name="child" hint="The child to check"/>

		<cfscript>
			var local = {};
			local.childsParent = "";

			if(!isObject(arguments.child))
				throwException( getJava( "java.lang.NullPointerException" ).init( "child argument is null" ) );
			if(!arguments.child.isDirectory())
				return false;
			if(!isObject(arguments.parent))
				throwException( getJava( "java.lang.NullPointerException" ).init( "parent argument is null" ) );
			arguments.parent = arguments.parent.getCanonicalFile();
			arguments.child = arguments.child.getCanonicalFile();
			local.childsParent = arguments.child.getParentFile();
			if(local.childsParent == "")
				return false;// sym link to /?
			local.childsParent = local.childsParent.getCanonicalFile();// just in case...
			if(!arguments.parent.equals( local.childsParent ))
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
				throwException( getJava( "java.io.IOException" ).init( "Unable to delete file " & arguments.file.getAbsolutePath() ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="deleteRecursively" output="false"
	            hint="Recursively delete a file. If file is a directory, subdirectories and files are also deleted. Care is taken to not traverse symbolic links in this process. A null file or a file that does not exist is considered to already been deleted.">
		<cfargument required="true" name="file" hint="The file or directory to be deleted"/>

		<cfscript>
			var local = {};
			local.children = "";
			local.child = "";

			if(!isObject(arguments.file) || !arguments.file.exists())
				return;// already deleted?
			if(arguments.file.isDirectory()) {
				local.children = arguments.file.listFiles();
				for(local.i = 1; local.i <= arrayLen(local.children); local.i++) {
					local.child = local.children[local.i];
					if(isChildSubDirectory( arguments.file, local.child ))
						deleteRecursively( local.child );
					else
						delete( local.child );
				}
			}

			// finally
			delete( arguments.file );
		</cfscript>

	</cffunction>

</cfcomponent>
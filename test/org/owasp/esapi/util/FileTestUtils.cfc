<cfcomponent output="false">

	<cfscript>
		static.CLASS = getMetaData(this);
		static.CLASS_NAME = listLast(static.CLASS.name, ".");
		static.DEFAULT_PREFIX = static.CLASS_NAME & '.';
		static.DEFAULT_SUFFIX = ".tmp";
		secRand = createObject("java", "java.security.SecureRandom").init();
		instance.rand = createObject("java", "java.util.Random").init(secRand.nextLong());
	</cfscript>

	<cffunction access="public" returntype="String" name="toHexString" output="false" hint="Convert a long to it's hex representation. Unlike Long##toHexString(long) this always returns 16 digits.">
		<cfargument type="numeric" name="l" required="true" hint="The long to convert.">
		<cfscript>
			local.initial = createObject("java", "java.lang.Long").toHexString(arguments.l);
			if(local.initial.length() == 16) {
				return local.initial;
			}
			local.sb = createObject("java", "java.lang.StringBuffer").init(16);
			local.sb.append(local.initial);
			while(local.sb.length()<16) {
				local.sb.insert(0,'0');
			}
			return local.sb.toString();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="createTmpDirectory" output="false" hint="java.io.File: Create a temporary directory.">
		<cfargument type="any" name="parent" required="false" hint="java.io.File: The parent directory for the temporary directory. If this is null, the system property 'java.io.tmpdir' is used.">
		<cfargument type="String" name="prefix" required="false" default="#static.DEFAULT_PREFIX#" hint="The prefix for the directory's name. If this is null, the full class name of this class is used.">
		<cfargument type="String" name="suffix" required="false" default="#static.DEFAULT_SUFFIX#" hint="The suffix for the directory's name. If this is null, '.tmp' is used.">
		<cfscript>
			if(!arguments.prefix.endsWith(".")) {
				arguments.prefix &= ".";
			}
			if(!arguments.suffix.startsWith(".")) {
				arguments.suffix = "." & arguments.suffix;
			}
			if(isNull(arguments.parent)) {
				arguments.parent = createObject("java", "java.io.File").init(createObject("java", "java.lang.System").getProperty("java.io.tmpdir"));
			}
			local.name = arguments.prefix & toHexString(instance.rand.nextLong()) & arguments.suffix;
			local.dir = createObject("java", "java.io.File").init(arguments.parent, local.name);
			if(!local.dir.mkdir()) {
				throw(object=createObject("java", "java.io.IOException").init("Unable to create temporary directory " & local.dir));
			}
			return local.dir.getCanonicalFile();
		</cfscript>
	</cffunction>

	<!--- isChildSubDirectory --->

	<cffunction access="public" returntype="void" name="delete" output="false" hint="Delete a file. Unlinke File##delete(), this throws an exception if deletion fails.">
		<cfargument type="any" name="file" required="true" hint="java.io.File: The file to delete">
		<cfscript>
		if(isNull(arguments.file) || !arguments.file.exists()) {
			return;
		}
		if(!arguments.file.delete()) {
			throw(object=createObject("java", "java.io.IOException").init("Unable to delete file " & arguments.file.getAbsolutePath()));
		}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="deleteRecursively" output="false" hint="Recursively delete a file. If file is a directory, subdirectories and files are also deleted. Care is taken to not traverse symbolic links in this process. A null file or a file that does not exist is considered to already been deleted.">
		<cfargument type="any" name="file" required="true" hint="java.io.File: The file or directory to be deleted">
		<cfscript>
			if(!isObject(arguments.file) || !arguments.file.exists())
				return;	// already deleted?
			if(arguments.file.isDirectory()) {
				local.children = arguments.file.listFiles();
				for(local.i=0; local.i<arrayLen(local.children); local.i++) {
					local.child = local.children[local.i];
					if(isChildSubDirectory(arguments.file,local.child))
						deleteRecursively(local.child);
					else
						delete(local.child);
				}
			}

			// finally
			delete(arguments.file);
		</cfscript>
	</cffunction>


</cfcomponent>

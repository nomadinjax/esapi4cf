<cfcomponent extends="Object" output="false">

	<cfscript>
		instance.File = "";
	</cfscript>

	<cffunction access="public" returntype="File" name="init" output="false">
		<cfargument type="String" name="pathname">
		<cfargument name="parent">
		<cfargument type="String" name="child">
		<cfargument name="uri">

		<cfscript>
			if (structKeyExists(arguments, "pathname")) {
				instance.File = getJava("java.io.File").init(javaCast("string", arguments.pathname));
			}
			else if (structKeyExists(arguments, "parent") && structKeyExists(arguments, "child")) {
				instance.File = getJava("java.io.File").init(arguments.parent, javaCast("string", arguments.child));
			}
			else if (structKeyExists(arguments, "uri")) {
				instance.File = getJava("java.io.File").init(arguments.uri);
			}
			else {
				throwException(getJava("IOException").init("Invalid File Instantiation.", "You must provide either a pathname, a parent and child, or a uri."));
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
			return instance.File.exists();
		</cfscript>
	</cffunction>

	<!---getAbsoluteFile()
	getAbsolutePath()
	getCanonicalFile()
	getCanonicalPath()--->

	<cffunction access="public" returntype="String" name="getName" output="false">
		<cfscript>
			return instance.File.getName();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getParent" output="false">
		<cfscript>
			return instance.File.getParent();
		</cfscript>
	</cffunction>

	<!---getParentFile() --->

	<cffunction access="public" returntype="String" name="getPath" output="false">
		<cfscript>
			return instance.File.getPath();
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
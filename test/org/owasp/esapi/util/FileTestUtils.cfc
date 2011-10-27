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
/**
 * Utilities to help with tests that involve files or directories.
 */
component FileTestUtils extends="cfesapi.org.owasp.esapi.lang.Object" {

	// imports
	instance.CLASS = getMetaData(this);
	instance.CLASS_NAME = listLast(instance.CLASS.name, ".");
	instance.DEFAULT_PREFIX = instance.CLASS_NAME & ".";
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
	instance.secRand = newJava("java.security.SecureRandom").init();
	instance.rand = newJava("java.util.Random").init(instance.secRand.nextLong());

	/**
	 * Convert a long to it's hex representation. Unlike
	 * {@ Long#toHexString(long)} this always returns 16 digits.
	 * @param l The long to convert.
	 * @return l in hex.
	 */
	
	public String function toHexString(required numeric l) {
		local.initial = "";
		local.sb = "";
	
		local.initial = newJava("java.lang.Long").toHexString(arguments.l);
		if(local.initial.length() == 16) {
			return local.initial;
		}
		local.sb = newJava("java.lang.StringBuffer").init(javaCast("int", 16));
		local.sb.append(local.initial);
		while(local.sb.length() < 16) {
			local.sb.insert(0, '0');
		}
		return local.sb.toString();
	}
	
	/**
	 * Create a temporary directory.
	 * @param parent The parent directory for the temporary
	 *    directory. If this is null, the system property
	 *     "java.io.tmpdir" is used.
	 * @param prefix The prefix for the directory's name. If this
	 *     is null, the full class name of this class is used.
	 * @param suffix The suffix for the directory's name. If this
	 *     is null, ".tmp" is used.
	 * @return The newly created temporary directory.
	 * @throws IOException if directory creation fails
	 * @throws SecurityException if {@link File#mkdir()} throws one.
	 */
	
	public function createTmpDirectory(parent, String prefix, String suffix) {
		local.name = "";
		local.dir = "";
	
		if(isNull(arguments.prefix)) {
			arguments.prefix = instance.DEFAULT_PREFIX;
		}
		else if(!arguments.prefix.endsWith(".")) {
			arguments.prefix &= ".";
		}
		if(isNull(arguments.suffix)) {
			arguments.suffix = instance.DEFAULT_SUFFIX;
		}
		else if(!arguments.suffix.startsWith(".")) {
			arguments.suffix = "." & arguments.suffix;
		}
		if(isNull(arguments.parent)) {
			arguments.parent = newJava("java.io.File").init(newJava("java.lang.System").getProperty("java.io.tmpdir"));
		}
		local.name = arguments.prefix & toHexString(instance.rand.nextLong()) & arguments.suffix;
		local.dir = newJava("java.io.File").init(arguments.parent, local.name);
		if(!local.dir.mkdir()) {
			throwError(newJava("java.io.IOException").init("Unable to create temporary directory " & local.dir));
		}
		return local.dir.getCanonicalFile();
	}
	
	/**
	 * Checks that child is a directory and really a child of
	 * parent. This verifies that the {@link File#getCanonicalFile()
	 * canonical} child is actually a child of parent. This should
	 * fail if the child is a symbolic link to another directory and
	 * therefore should not be traversed in a recursive traversal of
	 * a directory.
	 * @param parent The supposed parent of the child
	 * @param child The child to check
	 * @return true if child is a directory and a direct decendant
	 *     of parent.
	 * @throws IOException if {@link File#getCanonicalFile()} does
	 * @throws NullPointerException if either parent or child
	 *     are null.
	 */
	
	public boolean function isChildSubDirectory(required parent, required child) {
		local.childsParent = "";
	
		if(isNull(arguments.child)) {
			throw new NullPointerException("child argument is null");
		}
		if(!arguments.child.isDirectory()) {
			return false;
		}
		if(isNull(arguments.parent)) {
			throw new NullPointerException("parent argument is null");
		}
		arguments.parent = arguments.parent.getCanonicalFile();
		arguments.child = arguments.child.getCanonicalFile();
		local.childsParent = arguments.child.getParentFile();
		if(isNull(local.childsParent)) {
			return false;// sym link to /?
		}
		local.childsParent = local.childsParent.getCanonicalFile();// just in case...
		if(!arguments.parent.equals(local.childsParent)) {
			return false;
		}
		return true;
	}
	
	/**
	 * Delete a file. Unlinke {@link File#delete()}, this throws an
	 * exception if deletion fails.
	 * @param file The file to delete
	 * @throws IOException if file is not null, exists but delete
	 *     fails.
	 */
	
	public void function delete(required file) {
		if(isNull(arguments.file) || !arguments.file.exists()) {
			return;
		}
		if(!arguments.file.delete()) {
			throwError(newJava("java.io.IOException").init("Unable to delete file " & arguments.file.getAbsolutePath()));
		}
	}
	
	/**
	 * Recursively delete a file. If file is a directory,
	 * subdirectories and files are also deleted. Care is taken to
	 * not traverse symbolic links in this process. A null file or
	 * a file that does not exist is considered to already been
	 * deleted.
	 * @param file The file or directory to be deleted
	 * @throws IOException if the file, or a descendant, cannot
	 *     be deleted.
	 * @throws SecurityException if {@link File#delete()} does.
	 */
	
	public void function deleteRecursively(required file) {
		local.children = "";
		local.child = "";
	
		if(!isObject(arguments.file) || !arguments.file.exists()) {
			return;// already deleted?
		}
		if(arguments.file.isDirectory()) {
			local.children = arguments.file.listFiles();
			for(local.i = 0; local.i < arrayLen(local.children); local.i++) {
				local.child = local.children[local.i];
				if(isChildSubDirectory(arguments.file, local.child)) {
					deleteRecursively(local.child);
				}
				else {
					delete(local.child);
				}
			}
		}
	
		// finally
		delete(arguments.file);
	}
	
}
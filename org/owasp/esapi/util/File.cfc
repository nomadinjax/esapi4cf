/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
component extends="Object" {

	variables.File = createObject("java", "java.io.File");

	/**
	 * The system-dependent path-separator character, represented as a string for convenience.
	 */
	this.pathSeparator = variables.File.pathSeparator;

	/**
	 * The system-dependent path-separator character.
	 */
	this.pathSeparatorChar = variables.File.pathSeparatorChar;

	/**
	 * The system-dependent default name-separator character, represented as a string for convenience.
	 */
	this.separator = variables.File.separator;

	/**
	 * The system-dependent default name-separator character.
	 */
	this.separatorChar = variables.File.separatorChar;

	/**
	 * Creates a new File instance one of four ways:
	 * - Creates a new File instance by converting the given pathname string into an abstract pathname. If the given string is the empty string, then the result is the empty abstract pathname.
	 * - Creates a new File instance from a parent pathname string and a child pathname string.
	 * - Creates a new File instance from a parent abstract pathname and a child pathname string.
	 * - Creates a new File instance by converting the given file: URI into an abstract pathname.
	 *
	 * @pathname A pathname string
	 * @parent The parent pathname string OR The parent abstract pathname
	 * @child The child pathname string
	 * @uri An absolute, hierarchical URI with a scheme equal to "file", a non-empty path component, and undefined authority, query, and fragment components
	 */
	public File function init(string pathname, parent, string child, uri) {
		if (structKeyExists(arguments, "pathname") && !isNull(arguments.pathname)) {
			variables.File = variables.File.init(javaCast("string", arguments.pathname));
		}
		else if (structKeyExists(arguments, "parent") && !isNull(arguments.parent) && structKeyExists(arguments, "child") && !isNull(arguments.child)) {
			variables.File = variables.File.init(arguments.parent, javaCast("string", arguments.child));
		}
		else if (structKeyExists(arguments, "uri") && !isNull(arguments.uri)) {
			variables.File = variables.File.init(arguments.uri);
		}
		else {
			throws(createObject("java", "java.io.IOException").init("Invalid File Instantiation.", "You must provide either a path, a parent and child, or a uri."));
		}

		return this;
	}

	/**
	 * Tests whether the application can execute the file denoted by this abstract pathname.
	 */
	public boolean function canExecute() {
		return variables.File.canExecute();
	}

	/**
	 * Tests whether the application can read the file denoted by this abstract pathname.
	 */
	public boolean function canRead() {
		return variables.File.canRead();
	}

	/**
	 * Tests whether the application can modify the file denoted by this abstract pathname.
	 */
	public boolean function canWrite() {
		return variables.File.canWrite();
	}

	/**
	 * Compares two abstract pathnames lexicographically.
	 */
	public boolean function compareTo(required pathname) {
		return variables.File.compareTo(arguments.pathname);
	}

	/**
	 * Atomically creates a new, empty file named by this abstract pathname if and only if a file with this name does not yet exist.
	 */
	public boolean function createNewFile() {
		return variables.File.createNewFile();
	}

	/**
	 * Creates a new empty file in the specified directory, using the given prefix and suffix strings to generate its name.
	 */
	public boolean function createTempFile(required string prefix, required string suffix, string directory=getTempDirectory()) {
		return variables.File.createTempFile(javaCast("string", arguments.prefix), javaCast("string", arguments.suffix), arguments.directory);
	}

	/**
	 * Deletes the file or directory denoted by this abstract pathname.
	 */
	public boolean function delete() {
		return variables.File.delete();
	}

	/**
	 * Requests that the file or directory denoted by this abstract pathname be deleted when the virtual machine terminates.
	 */
	public void function deleteOnExit() {
		return variables.File.deleteOnExit();
	}

	/**
	 * Tests this abstract pathname for equality with the given object.
	 */
	public boolean function isEquals(required obj) {
		return variables.File.equals(obj);
	}

	/**
	 * Tests whether the file or directory denoted by this abstract pathname exists.
	 */
	public boolean function exists() {
		return variables.File.exists();
	}

	/**
	 * Returns the absolute form of this abstract pathname.
	 */
	public function getAbsoluteFile() {
		return variables.File.getAbsoluteFile();
	}

	/**
	 * Returns the absolute pathname string of this abstract pathname.
	 */
	public string function getAbsolutePath() {
		return variables.File.getAbsolutePath();
	}

	/**
	 * Returns the canonical form of this abstract pathname.
	 */
	public function getCanonicalFile() {
		return variables.File.getCanonicalFile();
	}

	/**
	 * Returns the canonical pathname string of this abstract pathname.
	 */
	public string function getCanonicalPath() {
		return variables.File.getCanonicalPath();
	}

	/**
	 * Returns the number of unallocated bytes in the partition named by this abstract path name.
	 */
	public numeric function getFreeSpace() {
		return variables.File.getFreeSpace();
	}

	/**
	 * Returns the name of the file or directory denoted by this abstract pathname.
	 */
	public string function getName() {
		return variables.File.getName();
	}

	/**
	 * Returns the pathname string of this abstract pathname's parent, or null if this pathname does not name a parent directory.
	 */
	public function getParent() {
		return variables.File.getParent();
	}

	/**
	 * Returns the abstract pathname of this abstract pathname's parent, or null if this pathname does not name a parent directory.
	 */
	public function getParentFile() {
		return variables.File.getParentFile();
	}

	/**
	 * Converts this abstract pathname into a pathname string.
	 */
	public string function getPath() {
		return variables.File.getPath();
	}

	/**
	 * Returns the size of the partition named by this abstract pathname.
	 */
	public numeric function getTotalSpace() {
		return variables.File.getTotalSpace();
	}

	/**
	 * Returns the number of bytes available to this virtual machine on the partition named by this abstract pathname.
	 */
	public numeric function getUsableSpace() {
		return variables.File.getUsableSpace();
	}

	/**
	 * Computes a hash code for this abstract pathname.
	 */
	public numeric function hashCode() {
		return variables.File.hashCode();
	}

	/**
	 * Tests whether this abstract pathname is absolute.
	 */
	public boolean function isAbsolute() {
		return variables.File.isAbsolute();
	}

	/**
	 * Tests whether the file denoted by this abstract pathname is a directory.
	 */
	public boolean function isDirectory() {
		return variables.File.isDirectory();
	}

	/**
	 * Tests whether the file denoted by this abstract pathname is a normal file.
	 */
	public boolean function isFile() {
		return variables.File.isFile();
	}

	/**
	 * Tests whether the file named by this abstract pathname is a hidden file.
	 */
	public string function isHidden() {
		return variables.File.isHidden();
	}

	/**
	 * Returns the time that the file denoted by this abstract pathname was last modified.
	 */
	public date function lastModified() {
		return variables.File.lastModified();
	}

	/**
	 * Returns the length of the file denoted by this abstract pathname.
	 */
	public numeric function length() {
		return variables.File.length();
	}

	/**
	 * Returns an array of strings naming the files and directories in the directory denoted by this abstract pathname that satisfy the specified filter.
	 */
	public array function list(filter) {
		if (structKeyExists(arguments, "filter")) {
			return variables.File.list(arguments.filter);
		}
		else {
			return variables.File.list();
		}
	}

	/**
	 * Returns an array of abstract pathnames denoting the files and directories in the directory denoted by this abstract pathname that satisfy the specified filter.
	 */
	public array function listFiles(filter) {
		if (structKeyExists(arguments, "filter")) {
			return variables.File.listFiles(arguments.filter);
		}
		else {
			return variables.File.listFiles();
		}
	}

	/**
	 * List the available filesystem roots.
	 */
	public array function listRoots() {
		return variables.File.listRoots();
	}

	/**
	 * Creates the directory named by this abstract pathname.
	 */
	public boolean function mkdir() {
		return variables.File.mkdir();
	}

	/**
	 * Creates the directory named by this abstract pathname, including any necessary but nonexistent parent directories.
	 */
	public boolean function mkdirs() {
		return variables.File.mkdirs();
	}

	/**
	 * Renames the file denoted by this abstract pathname.
	 */
	public boolean function renameTo(required dest) {
		return variables.File.renameTo(arguments.dest);
	}

	/**
	 * Sets the owner's or everybody's execute permission for this abstract pathname.
	 */
	public boolean function setExecutable(required boolean executable, boolean ownerOnly) {
		if (structKeyExists(arguments, "ownerOnly")) {
			return variables.File.setExecutable(javaCast("boolean", arguments.executable), javaCast("boolean", arguments.ownerOnly));
		}
		else {
			return variables.File.setExecutable(javaCast("boolean", arguments.executable));
		}
	}

	/**
	 * Sets the last-modified time of the file or directory named by this abstract pathname.
	 */
	public boolean function setLastModified(required date time) {
		return variables.File.setLastModified(javaCast("long", arguments.time.getTime()));
	}

	/**
	 * Sets the owner's or everybody's read permission for this abstract pathname.
	 */
	public boolean function setReadable(required boolean readable, boolean ownerOnly) {
		if (structKeyExists(arguments, "ownerOnly")) {
			return variables.File.setExecutable(javaCast("boolean", arguments.readable), javaCast("boolean", arguments.ownerOnly));
		}
		else {
			return variables.File.setExecutable(javaCast("boolean", arguments.readable));
		}
	}

	/**
	 * Marks the file or directory named by this abstract pathname so that only read operations are allowed.
	 */
	public boolean function setReadOnly() {
		return variables.File.setReadOnly();
	}

	/**
	 * Sets the owner's or everybody's write permission for this abstract pathname.
	 */
	public boolean function setWritable(required boolean writable, boolean ownerOnly) {
		if (structKeyExists(arguments, "ownerOnly")) {
			return variables.File.setExecutable(javaCast("boolean", arguments.writable), javaCast("boolean", arguments.ownerOnly));
		}
		else {
			return variables.File.setExecutable(javaCast("boolean", arguments.writable));
		}
	}

	/**
	 * Returns a java.nio.file.Path object constructed from the this abstract path.
	 */
	public function toPath() {
		return variables.File.toPath();
	}

	/**
	 * Returns the pathname string of this abstract pathname.
	 */
	public string function toString() {
		return variables.File.toString();
	}

	/**
	 * Constructs a file: URI that represents this abstract pathname.
	 */
	public function toURI() {
		return variables.File.toURI();
	}

	/* *** convenience methods *** */

	/**
	 * Returns the canonical path name.
	 */
	public string function getPathName() {
		// files need to access parent to get JUST directory path; directories should return self
		return this.isFile() ? this.getParentFile().getCanonicalPath() : this.getCanonicalPath();
	}

	/**
	 * Returns the canonical file name.
	 */
	public string function getFileName() {
		return this.getCanonicalFile().getName();
	}

	/**
	 * Returns the canonical file extension.
	 */
	public string function getFileExtension() {
		var filename = this.getFileName();
		return listLen(filename, ".") > 1 ? listLast(filename, ".") : "";
	}

}
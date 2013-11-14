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
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		variables.origConfig = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			// save configuration as tests may change it
			variables.origConfig = variables.ESAPI.securityConfiguration();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			// restore configuration as test may change it
			variables.ESAPI.setSecurityConfiguration(variables.origConfig);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testExecuteWindowsSystemCommand" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var codec = "";
			var instance = "";
			var executable = "";
			var working = "";
			var params = "";
			var result = "";
			var exec2 = "";
			var workdir = "";

			System.out.println("executeWindowsSystemCommand");

			if(System.getProperty("os.name").indexOf("Windows") == -1) {
				System.out.println("testExecuteWindowsSystemCommand - on non-Windows platform, exiting");
				return;// Not windows, not going to execute this path
			}

			codec = newJava("org.owasp.esapi.codecs.WindowsCodec").init();
			System.out.println("executeSystemCommand");
			instance = variables.ESAPI.executor();
			executable = newJava("java.io.File").init("C:\\Windows\\System32\\cmd.exe");
			working = newJava("java.io.File").init("C:\\");
			params = newJava("java.util.ArrayList").init();
			try {
				params.add("dir");
				params.add("/C");
				result = instance.executeSystemCommand(executable, params, working, codec);
				System.out.println("RESULT: " & result);
				assertTrue(result.length() > 0);
			}
			catch(java.lang.Exception e) {
				fail(e.getMessage());
			}
			try {
				exec2 = newJava("java.io.File").init(executable.getPath() & ";inject.exe");
				result = instance.executeSystemCommand(exec2, params, working, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				exec2 = newJava("java.io.File").init(executable.getPath() & "\\..\\cmd.exe");
				result = instance.executeSystemCommand(exec2, params, working, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				workdir = newJava("java.io.File").init("ridiculous");
				result = instance.executeSystemCommand(executable, params, workdir, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				params.add("&dir");
				result = instance.executeSystemCommand(executable, params, working, codec);
				System.out.println("RESULT: " & result);
			}
			catch(java.lang.Exception e) {
				fail("");
			}

			try {
				params.set(params.size() - 1, "c:\\autoexec.bat");
				result = instance.executeSystemCommand(executable, params, working, codec);
				System.out.println("RESULT: " & result);
			}
			catch(java.lang.Exception e) {
				fail("");
			}

			try {
				params.set(params.size() - 1, "c:\\autoexec.bat c:\\config.sys");
				result = instance.executeSystemCommand(executable, params, working, codec);
				System.out.println("RESULT: " & result);
			}
			catch(java.lang.Exception e) {
				fail("");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testExecuteUnixSystemCommand" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var workingDir = "";
			var codec = "";
			var binSh = "";
			var instance = "";
			var executable = "";
			var params = "";
			var result = "";
			var exec2 = "";

			System.out.println("executeUnixSystemCommand");
			workingDir = newJava("java.io.File").init("/tmp");

			if(System.getProperty("os.name").indexOf("Windows") != -1) {
				System.out.println("executeUnixSystemCommand - on Windows platform, exiting");
				return;
			}

			// FIXME: need more test cases to use this codec
			codec = newJava("org.owasp.esapi.codecs.UnixCodec").init();

			// make sure we have what /bin/sh is pointing at in the allowed exes for the test
			// and a usable working dir
			binSh = newJava("java.io.File").init("/bin/sh").getCanonicalFile();
			variables.ESAPI.setSecurityConfiguration(createObject("component", "ExecutorTest$Conf").init(variables.ESAPI.securityConfiguration(), newJava("java.util.Collections").singletonList(binSh.getPath()), workingDir));

			instance = variables.ESAPI.executor();
			executable = binSh;
			params = [];
			try {
				params.add("-c");
				params.add("ls");
				params.add("/");
				result = instance.executeSystemCommand(executable, params, workingDir, codec);
				System.out.println("RESULT: " & result);
				assertTrue(result.length() > 0);
			}
			catch(Exception e) {
				fail(e.getMessage());
			}
			try {
				exec2 = newJava("java.io.File").init(executable.getPath() & ";./inject");
				result = instance.executeSystemCommand(exec2, params, workingDir, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(Exception e) {
				// expected
			}
			try {
				exec2 = newJava("java.io.File").init(executable.getPath() & "/../bin/sh");
				result = instance.executeSystemCommand(exec2, params, workingDir, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(Exception e) {
				// expected
			}
			try {
				params.add(";ls");
				result = instance.executeSystemCommand(executable, params, workingDir, codec);
				System.out.println("RESULT: " & result);
			}
			catch(Exception e) {
				fail("");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testExecuteSystemCommand" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var tmpDir = "";
			var javaHome = "";
			var javaHomeBin = "";
			var javaHomeBinJava = "";
			var instance = variables.ESAPI.executor();
			var params = [];
			var result = "";
			var codec = "";
			var javaCmd = "";
			System.out.println("executeSystemCommand");

			if(System.getProperty("os.name").indexOf("Windows") >= 0) {
				codec = newJava("org.owasp.esapi.codecs.WindowsCodec").init();
				javaCmd = "java.exe";
			}
			else {
				javaCmd = "java";
				codec = newJava("org.owasp.esapi.codecs.UnixCodec").init();
			}

			javaHome = newJava("java.io.File").init(System.getProperty("java.home")).getCanonicalFile();
			assertTrue(javaHome.isDirectory(), "system property java.home does not point to a directory");
			javaHomeBin = newJava("java.io.File").init(javaHome, "bin").getCanonicalFile();
			assertTrue(javaHome.isDirectory(), javaHome.getPath() & newJava("java.io.File").separator & "bin does not exist");
			javaHomeBinJava = newJava("java.io.File").init(javaHomeBin, javaCmd).getCanonicalFile();
			assertTrue(javaHomeBinJava.exists(), javaHomeBinJava.getPath() & newJava("java.io.File").separator & "java does not exist");

			tmpDir = newJava("java.io.File").init(System.getProperty("java.io.tmpdir")).getCanonicalFile();
			assertTrue(tmpDir.isDirectory(), "system property java.io.tmpdir does not point to a directory");

			variables.ESAPI.setSecurityConfiguration(createObject("component", "ExecutorTest$Conf").init(variables.ESAPI.securityConfiguration(), newJava("java.util.Collections").singletonList(javaHomeBinJava.getPath()), tmpDir));
			// -version goes to stderr which executeSystemCommand doesn't read...
			// -help goes to stdout so we'll use that...
			params.add("-help");

			result = instance.executeSystemCommand(javaHomeBinJava, params, tmpDir, codec);
			assertFalse(result == "", "result of java -version was null");
			assertTrue(result.indexOf("-version") >= 0, "result of java -help did not contain -version");
		</cfscript>

	</cffunction>

</cfcomponent>
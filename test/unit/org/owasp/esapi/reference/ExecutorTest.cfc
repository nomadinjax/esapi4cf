<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="esapi4cf.test.unit.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		variables.origConfig = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			// save configuration as tests may change it
			variables.origConfig = request.ESAPI.securityConfiguration();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			// restore configuration as test may change it
			request.ESAPI.setSecurityConfiguration(variables.origConfig);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testExecuteWindowsSystemCommand" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var jFile = createObject("java", "java.io.File");
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

			codec = createObject("java", "org.owasp.esapi.codecs.WindowsCodec").init();
			System.out.println("executeSystemCommand");
			instance = request.ESAPI.executor();
			executable = jFile.init("C:\\Windows\\System32\\cmd.exe");
			working = jFile.init("C:\\");
			params = createObject("java", "java.util.ArrayList").init();
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
				exec2 = jFile.init(executable.getPath() & ";inject.exe");
				result = instance.executeSystemCommand(exec2, params, working, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				exec2 = jFile.init(executable.getPath() & "\\..\\cmd.exe");
				result = instance.executeSystemCommand(exec2, params, working, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				workdir = jFile.init("ridiculous");
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
			var jFile = createObject("java", "java.io.File");
			var workingDir = "";
			var codec = "";
			var binSh = "";
			var instance = "";
			var executable = "";
			var params = "";
			var result = "";
			var exec2 = "";

			System.out.println("executeUnixSystemCommand");
			workingDir = jFile.init("/tmp");

			if(System.getProperty("os.name").indexOf("Windows") != -1) {
				System.out.println("executeUnixSystemCommand - on Windows platform, exiting");
				return;
			}

			// FIXME: need more test cases to use this codec
			codec = createObject("java", "org.owasp.esapi.codecs.UnixCodec").init();

			// make sure we have what /bin/sh is pointing at in the allowed exes for the test
			// and a usable working dir
			binSh = jFile.init("/bin/sh").getCanonicalFile();
			request.ESAPI.setSecurityConfiguration(createObject("component", "ExecutorTest$Conf").init(request.ESAPI.securityConfiguration(), createObject("java", "java.util.Collections").singletonList(binSh.getPath()), workingDir));

			instance = request.ESAPI.executor();
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
				exec2 = jFile.init(executable.getPath() & ";./inject");
				result = instance.executeSystemCommand(exec2, params, workingDir, codec);
				System.out.println("RESULT: " & result);
				fail("");
			}
			catch(Exception e) {
				// expected
			}
			try {
				exec2 = jFile.init(executable.getPath() & "/../bin/sh");
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
			var jFile = createObject("java", "java.io.File");
			var tmpDir = "";
			var javaHome = "";
			var javaHomeBin = "";
			var javaHomeBinJava = "";
			var instance = request.ESAPI.executor();
			var params = [];
			var result = "";
			var codec = "";
			var javaCmd = "";
			System.out.println("executeSystemCommand");

			if(System.getProperty("os.name").indexOf("Windows") >= 0) {
				codec = createObject("java", "org.owasp.esapi.codecs.WindowsCodec").init();
				javaCmd = "java.exe";
			}
			else {
				javaCmd = "java";
				codec = createObject("java", "org.owasp.esapi.codecs.UnixCodec").init();
			}

			javaHome = jFile.init(System.getProperty("java.home")).getCanonicalFile();
			assertTrue(javaHome.isDirectory(), "system property java.home does not point to a directory");
			javaHomeBin = jFile.init(javaHome, "bin").getCanonicalFile();
			assertTrue(javaHome.isDirectory(), javaHome.getPath() & jFile.separator & "bin does not exist");
			javaHomeBinJava = jFile.init(javaHomeBin, javaCmd).getCanonicalFile();
			assertTrue(javaHomeBinJava.exists(), javaHomeBinJava.getPath() & jFile.separator & "java does not exist");

			tmpDir = jFile.init(System.getProperty("java.io.tmpdir")).getCanonicalFile();
			assertTrue(tmpDir.isDirectory(), "system property java.io.tmpdir does not point to a directory");

			request.ESAPI.setSecurityConfiguration(createObject("component", "ExecutorTest$Conf").init(request.ESAPI.securityConfiguration(), createObject("java", "java.util.Collections").singletonList(javaHomeBinJava.getPath()), tmpDir));
			// -version goes to stderr which executeSystemCommand doesn't read...
			// -help goes to stdout so we'll use that...
			params.add("-help");

			result = instance.executeSystemCommand(javaHomeBinJava, params, tmpDir, codec);
			assertFalse(result == "", "result of java -version was null");
			assertTrue(result.indexOf("-version") >= 0, "result of java -help did not contain -version");
		</cfscript>

	</cffunction>

</cfcomponent>
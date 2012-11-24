<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
--->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();

		instance.origConfig = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			// save configuration as tests may change it
			instance.origConfig = instance.ESAPI.securityConfiguration();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			// restore configuration as test may change it
			instance.ESAPI.setSecurityConfiguration(instance.origConfig);
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testExecuteWindowsSystemCommand" output="false">
		<cfscript>
			var local = {};

			System.out.println("executeWindowsSystemCommand");

			if ( System.getProperty("os.name").indexOf("Windows") == -1 ) {
				System.out.println("testExecuteWindowsSystemCommand - on non-Windows platform, exiting");
				return;	// Not windows, not going to execute this path
			}

			local.codec = getJava("org.owasp.esapi.codecs.WindowsCodec").init();
			System.out.println("executeSystemCommand");
			local.executor = instance.ESAPI.executor();
			local.executable = getJava("java.io.File").init( "C:\\Windows\\System32\\cmd.exe" );
			local.working = getJava("java.io.File").init("C:\\");
			local.params = [];
			try {
				local.params.add("/C");
				local.params.add("dir");
				local.result = local.executor.executeSystemCommand(local.executable, local.params, local.working, local.codec);
				System.out.println( "RESULT: " & local.result );
				assertTrue(local.result.length() > 0);
			} catch (java.lang.Exception e) {
				fail(e.getMessage());
			}
			try {
				local.exec2 = getJava("java.io.File").init( executable.getPath() & ";inject.exe" );
				local.result = local.executor.executeSystemCommand(local.exec2, local.params, local.working, local.codec);
				System.out.println( "RESULT: " & local.result );
				fail("");
			} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				local.exec2 = getJava("java.io.File").init( executable.getPath() & "\\..\\cmd.exe" );
				local.result = local.executor.executeSystemCommand(local.exec2, local.params, local.working, local.codec);
				System.out.println( "RESULT: " & result );
				fail("");
			} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				local.workdir = getJava("java.io.File").init( "ridiculous" );
				local.result = local.executor.executeSystemCommand(local.executable, local.params, local.workdir, local.codec);
				System.out.println( "RESULT: " & local.result );
				fail("");
			} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
				// expected
			}
			try {
				local.params.add("&dir");
				local.result = local.executor.executeSystemCommand(local.executable, local.params, local.working, local.codec);
				System.out.println( "RESULT: " & local.result );
			} catch (java.lang.Exception e) {
				fail("");
			}

			try {
				local.params.set( local.params.size()-1, "c:\\autoexec.bat" );
				local.result = local.executor.executeSystemCommand(local.executable, local.params, local.working, local.codec);
				System.out.println( "RESULT: " & local.result );
			} catch (java.lang.Exception e) {
				fail("");
			}

			try {
				local.params.set( local.params.size()-1, "c:\\autoexec.bat c:\\config.sys" );
				local.result = local.executor.executeSystemCommand(local.executable, local.params, local.working, local.codec);
				System.out.println( "RESULT: " & local.result );
			} catch (java.lang.Exception e) {
				fail("");
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testExecuteUnixSystemCommand" output="false">
		<cfscript>
			var local = {};

			System.out.println("executeUnixSystemCommand");
			local.workingDir = getJava("java.io.File").init("/tmp");

			if ( System.getProperty("os.name").indexOf("Windows") != -1 ) {
				System.out.println("executeUnixSystemCommand - on Windows platform, exiting");
				return;
			}

			// FIXME: need more test cases to use this codec
			local.codec = getJava("org.owasp.esapi.codecs.UnixCodec").init();

			// make sure we have what /bin/sh is pointing at in the allowed exes for the test
			// and a usable working dir
			local.binSh = getJava("java.io.File").init("/bin/sh").getCanonicalFile();
			instance.ESAPI.setSecurityConfiguration(
					createObject("component", "ExecutorTest$Conf").init(
						instance.ESAPI.securityConfiguration(),
						getJava("java.util.Collections").singletonList(local.binSh.getPath()),
						local.workingDir
						)
					);

			local.executor = instance.ESAPI.executor();
			local.executable = local.binSh;
			local.params = [];
			try {
				local.params.add("-c");
				local.params.add("ls");
				local.params.add("/");
				local.result = local.executor.executeSystemCommand(local.executable, local.params, local.workingDir, local.codec);
				System.out.println( "RESULT: " & result );
				assertTrue(local.result.length() > 0);
			} catch (Exception e) {
				fail(e.getMessage());
			}
			try {
				local.exec2 = getJava("java.io.File").init( local.executable.getPath() & ";./inject" );
				local.result = local.executor.executeSystemCommand(local.exec2, local.params, local.workingDir, local.codec);
				System.out.println( "RESULT: " & local.result );
				fail("");
			} catch (Exception e) {
				// expected
			}
			try {
				local.exec2 = getJava("java.io.File").init( executable.getPath() & "/../bin/sh" );
				local.result = local.executor.executeSystemCommand(local.exec2, local.params, local.workingDir, local.codec);
				System.out.println( "RESULT: " & local.result );
				fail("");
			} catch (Exception e) {
				// expected
			}
			try {
				params.add(";ls");
				local.result = local.executor.executeSystemCommand(local.executable, local.params, local.workingDir, local.codec);
				System.out.println( "RESULT: " & local.result );
			} catch (Exception e) {
				fail("");
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testExecuteSystemCommand" output="false">
		<cfscript>
			var local = {};

			System.out.println("executeSystemCommand");
			local.tmpDir = "";
			local.javaHome = "";
			local.javaHomeBin = "";
			local.javaHomeBinJava = "";
			local.executor = instance.ESAPI.executor();
			local.params = [];
			local.result = "";
			local.codec = "";
			local.javaCmd = "";

			if (System.getProperty("os.name").indexOf("Windows") >= 0)
			{
				local.codec = getJava("org.owasp.esapi.codecs.WindowsCodec").init();
				local.javaCmd = "java.exe";
			}
			else
			{
				local.javaCmd = "java";
				local.codec = getJava("org.owasp.esapi.codecs.UnixCodec").init();
			}

			local.javaHome = getJava("java.io.File").init(System.getProperty("java.home")).getCanonicalFile();
			assertTrue(local.javaHome.isDirectory(), "system property java.home does not point to a directory");
			local.javaHomeBin = getJava("java.io.File").init(local.javaHome, "bin").getCanonicalFile();
			assertTrue(local.javaHome.isDirectory(), javaHome.getPath() & getJava("java.io.File").separator & "bin does not exist");
			local.javaHomeBinJava = getJava("java.io.File").init(local.javaHomeBin, local.javaCmd).getCanonicalFile();
			assertTrue(local.javaHomeBinJava.exists(), javaHomeBinJava.getPath() & getJava("java.io.File").separator & "java does not exist");

			local.tmpDir = getJava("java.io.File").init(System.getProperty("java.io.tmpdir")).getCanonicalFile();
			assertTrue(local.tmpDir.isDirectory(), "system property java.io.tmpdir does not point to a directory");

			instance.ESAPI.setSecurityConfiguration(
					createObject("component", "ExecutorTest$Conf").init(
						instance.ESAPI.securityConfiguration(),
						getJava("java.util.Collections").singletonList(local.javaHomeBinJava.getPath()),
						local.tmpDir
						)
					);
			// -version goes to stderr which executeSystemCommand doesn't read...
			// -help goes to stdout so we'll use that...
			local.params.add("-help");

			local.result = local.executor.executeSystemCommand(local.javaHomeBinJava, local.params, local.tmpDir, local.codec);
			assertFalse(local.result == "", "result of java -version was null");
			assertTrue(local.result.indexOf("-version") >= 0, "result of java -help did not contain -version");
		</cfscript>
	</cffunction>

</cfcomponent>

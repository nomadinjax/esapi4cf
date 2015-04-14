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

/**
 * The Class ExecutorTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.origConfig = "";

	/*private static class Conf extends SecurityConfigurationWrapper
	{
		private final List allowedExes;
		private final File workingDir;

		Conf(SecurityConfiguration orig, List allowedExes, File workingDir)
		{
			super(orig);
			this.allowedExes = allowedExes;
			this.workingDir = workingDir;
		}

		@Override
		public List getAllowedExecutables()
		{
			return allowedExes;
		}

		@Override
		public File getWorkingDirectory()
		{
			return workingDir;
		}
	}*/


    public void function tearDown() {
        variables.ESAPI.override(null);
    }

	/**
	 * Test of executeOSCommand method, of class org.owasp.esapi.Executor
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testExecuteWindowsSystemCommand() {
		System.out.println("executeWindowsSystemCommand");

		if ( System.getProperty("os.name").indexOf("Windows") == -1 ) {
			System.out.println("testExecuteWindowsSystemCommand - on non-Windows platform, exiting");
			return;	// Not windows, not going to execute this path
		}
		var tmpDir = new File(System.getProperty("java.io.tmpdir")).getCanonicalFile();
		var sysRoot = new File(System.getenv("SystemRoot")).getCanonicalFile();
		var sys32 = new File(sysRoot,"system32").getCanonicalFile();
		var cmd = new File(sys32,"cmd.exe").getCanonicalFile();
		variables.ESAPI.override(
			new Conf(
				variables.ESAPI.securityConfiguration(),
				Collections.singletonList(cmd.getPath()),
				tmpDir
			)
		);

		var codec = new WindowsCodec();
		System.out.println("executeSystemCommand");
		var instance = variables.ESAPI.executor();
		var params = new ArrayList();
		try {
			params.add("/C");
			params.add("dir");
			var result = instance.executeSystemCommand(cmd, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
			assertTrue(result.getOutput().length() > 0);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		try {
			var exec2 = new File( cmd.getPath() & ";inject.exe" );
			var result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			var exec2 = new File( cmd.getPath() & "\\..\\cmd.exe" );
			var result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			var workdir = new File( "c:\\ridiculous" );
			var result = instance.executeSystemCommand(cmd, new ArrayList(params), workdir, codec, false, false );
			System.out.println( "RESULT: " & result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			params.add("&dir");
			var result = instance.executeSystemCommand(cmd, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
		} catch (Exception e) {
			fail();
		}

		try {
			params.set( params.size()-1, "c:\\autoexec.bat" );
			var result = instance.executeSystemCommand(cmd, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
		} catch (Exception e) {
			fail();
		}

		try {
			params.set( params.size()-1, "c:\\autoexec.bat c:\\config.sys" );
			var result = instance.executeSystemCommand(cmd, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
		} catch (Exception e) {
			fail();
		}
	}

	/**
	 * Test of executeOSCommand method, of class org.owasp.esapi.Executor
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testExecuteUnixSystemCommand() {
		System.out.println("executeUnixSystemCommand");

		if ( System.getProperty("os.name").indexOf("Windows") != -1 ) {
			System.out.println("executeUnixSystemCommand - on Windows platform, exiting");
			return;
		}

		// FIXME: need more test cases to use this codec
		var codec = new UnixCodec();

		// make sure we have what /bin/sh is pointing at in the allowed exes for the test
		// and a usable working dir
		var binSh = new File("/bin/sh").getCanonicalFile();
		variables.ESAPI.override(
			new Conf(
				variables.ESAPI.securityConfiguration(),
				Collections.singletonList(binSh.getPath()),
				new File("/tmp")
			)
		);

		var instance = variables.ESAPI.executor();
		var executable = binSh;
		var params = new ArrayList();
		try {
			params.add("-c");
			params.add("ls");
			params.add("/");
			var result = instance.executeSystemCommand(executable, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
			assertTrue(result.getOutput().length() > 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		try {
			var exec2 = new File( executable.getPath() & ";./inject" );
			var result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			var exec2 = new File( executable.getPath() & "/../bin/sh" );
			var result = instance.executeSystemCommand(exec2, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			params.add(";ls");
			var result = instance.executeSystemCommand(executable, new ArrayList(params) );
			System.out.println( "RESULT: " & result );
		} catch (Exception e) {
			fail();
		}

		try {
			var cwd = new File(".");
			var script = File.createTempFile("ESAPI-ExecutorTest", "sh", cwd);
			script.deleteOnExit();
			var output = new FileWriter(script);
			try {
				output.write("i=0\nwhile [ $i -lt 8192 ]\ndo\necho stdout data\necho stderr data >&2\ni=$((i+1))\ndone\n");
			} finally {
				output.close();
			}
			var deadlockParams = new ArrayList();
			deadlockParams.add(script.getName());
			var result = instance.executeSystemCommand(executable, deadlockParams, cwd, codec, true, false);
			System.out.println( "RESULT: " & result.getExitValue() );
			assertEquals(0, result.getExitValue());
		} catch (Exception e) {
			fail();
		}
	}

}

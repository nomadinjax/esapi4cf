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
 * The Class ExecutorTest.
 */
component ExecutorTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {
	
	// import
	System = createObject("java", "java.lang.System");
	JavaFile = createObject("java", "java.io.File");
	//import java.util.ArrayList;
	//import java.util.Collections;
	//import java.util.List;
	
	//import org.owasp.esapi.ESAPI;
	//import org.owasp.esapi.ExecuteResult;
	//import org.owasp.esapi.Executor;
	//import org.owasp.esapi.SecurityConfiguration;
	//import org.owasp.esapi.SecurityConfigurationWrapper;
	//import org.owasp.esapi.codecs.Codec;

	instance.origConfig = "";

    // @Override
    public void function setup() {
		instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
    }
    
    // @Override
    public void function tearDown() {
        instance.ESAPI.override("");
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
		local.tmpDir = JavaFile.init(System.getProperty("java.io.tmpdir")).getCanonicalFile();
		local.sysRoot = JavaFile.init(System.getenv("SystemRoot")).getCanonicalFile();
		local.sys32 = JavaFile.init(local.sysRoot,"system32").getCanonicalFile();
		local.cmd = JavaFile.init(local.sys32,"cmd.exe").getCanonicalFile();
		instance.ESAPI.override(
			new ExecutorTest$Conf(
				instance.ESAPI.securityConfiguration(),
				listToArray(local.cmd.getPath()),
				local.tmpDir
			)
		);

		local.codec = createObject("java", "org.owasp.esapi.codecs.WindowsCodec").init();
		System.out.println("executeSystemCommand");
		local.executor = instance.ESAPI.executor();
		local.params = [];
		try {
			local.params.add("/C");
			local.params.add("dir");
			local.result = local.executor.executeSystemCommand(local.cmd, local.params);
			System.out.println( "RESULT: " & local.result );
			assertTrue(local.result.getOutput().length() > 0);
		} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
			e.printStackTrace();
			fail("");
		}
		try {
			local.exec2 = JavaFile.init( local.cmd.getPath() & ";inject.exe" );
			local.result = local.executor.executeSystemCommand(local.exec2, local.params);
			System.out.println( "RESULT: " & local.result );
			fail("");
		} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
			// expected
		}
		try {
			local.exec2 = JavaFile.init( local.cmd.getPath() & "\..\cmd.exe" );
			local.result = local.executor.executeSystemCommand(local.exec2, local.params);
			System.out.println( "RESULT: " & local.result );
			fail("");
		} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
			// expected
		}
		try {
			local.workdir = JavaFile.init( "c:\ridiculous" );
			local.result = local.executor.executeSystemCommand(local.cmd, local.params, local.workdir, local.codec, false, false );
			System.out.println( "RESULT: " & local.result );
			fail("");
		} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
			// expected
		}
		try {
			local.params.add("&dir");
			local.result = local.executor.executeSystemCommand(local.cmd, local.params);
			System.out.println( "RESULT: " & local.result );
		} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
			fail("");
		}

		try {
			local.params.set( local.params.size()-1, "c:\autoexec.bat" );
			local.result = local.executor.executeSystemCommand(local.cmd, local.params);
			System.out.println( "RESULT: " & local.result );
		} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
			fail("");
		}

		try {
			local.params.set( local.params.size()-1, "c:\autoexec.bat c:\config.sys" );
			local.result = local.executor.executeSystemCommand(local.cmd, local.params);
			System.out.println( "RESULT: " & local.result );
		} catch (cfesapi.org.owasp.esapi.errors.ExecutorException e) {
			fail("");
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
		local.codec = createObject("java", "org.owasp.esapi.codecs.UnixCodec");

		// make sure we have what /bin/sh is pointing at in the allowed exes for the test
		// and a usable working dir
		local.binSh = JavaFile.init("/bin/sh").getCanonicalFile();
		instance.ESAPI.override(
			new Conf(
				instance.ESAPI.securityConfiguration(),
				Collections.singletonList(local.binSh.getPath()),
				JavaFile.init("/tmp")
			)
		);

		local.executor = instance.ESAPI.executor();
		local.executable = local.binSh;
		local.params = new ArrayList();
		try {
			local.params.add("-c");
			local.params.add("ls");
			local.params.add("/");
			local.result = local.executor.executeSystemCommand(local.executable, new ArrayList(local.params) );
			System.out.println( "RESULT: " & local.result );
			assertTrue(local.result.getOutput().length() > 0);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		try {
			local.exec2 = JavaFile.init( local.executable.getPath() & ";./inject" );
			local.result = local.executor.executeSystemCommand(local.exec2, new ArrayList(local.params) );
			System.out.println( "RESULT: " & local.result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			local.exec2 = JavaFile.init( local.executable.getPath() & "/../bin/sh" );
			local.result = local.executor.executeSystemCommand(local.exec2, new ArrayList(local.params) );
			System.out.println( "RESULT: " & local.result );
			fail();
		} catch (Exception e) {
			// expected
		}
		try {
			local.params.add(";ls");
			local.result = local.executor.executeSystemCommand(local.executable, new ArrayList(local.params) );
			System.out.println( "RESULT: " & local.result );
		} catch (Exception e) {
			fail();
		}

		try {
			local.cwd = JavaFile.init(".");
			local.script = File.createTempFile("ESAPI-ExecutorTest", "sh", local.cwd);
			local.script.deleteOnExit();
			local.output = createObject("java", "java.io.FileWriter").init(local.script);
			try {
				local.output.write("i=0\nwhile [ $i -lt 8192 ]\ndo\necho stdout data\necho stderr data >&2\ni=$((i+1))\ndone\n");
			} finally {
				local.output.close();
			}
			local.deadlockParams = new ArrayList();
			local.deadlockParams.add(local.script.getName());
			local.result = local.executor.executeSystemCommand(local.executable, local.deadlockParams, local.cwd, local.codec, true, false);
			System.out.println( "RESULT: " & local.result.getExitValue() );
			assertEquals(0, local.result.getExitValue());
		} catch (Exception e) {
			fail();
		}
	}

}

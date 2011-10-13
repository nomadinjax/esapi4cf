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
<cfcomponent extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");
		
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
	</cfscript>
 
	<cffunction access="public" returntype="void" name="testExecuteWindowsSystemCommand" output="false" hint="Test of executeOSCommand method, of class org.owasp.esapi.Executor">
		<cfscript>
			ioFile = createObject("java", "java.io.File");
			Collections = createObject("java", "java.util.Collections");
			WindowsCodec = createObject("java", "org.owasp.esapi.codecs.WindowsCodec");

			System.out.println("executeWindowsSystemCommand");

			if ( System.getProperty("os.name").indexOf("Windows") == -1 ) {
				System.out.println("testExecuteWindowsSystemCommand - on non-Windows platform, exiting");
				return;	// Not windows, not going to execute this path
			}
			local.tmpDir = ioFile.init(System.getProperty("java.io.tmpdir")).getCanonicalFile();
			local.sysRoot = ioFile.init(System.getenv("SystemRoot")).getCanonicalFile();
			local.sys32 = ioFile.init(local.sysRoot,"system32").getCanonicalFile();
			local.cmd = ioFile.init(local.sys32,"cmd.exe").getCanonicalFile();
			instance.ESAPI.override(
				createObject("component", "Conf").init(
					instance.ESAPI.securityConfiguration(),
					Collections.singletonList(local.cmd.getPath()),
					local.tmpDir
				)
			);

			local.codec = WindowsCodec.init();
			System.out.println("executeSystemCommand");
			local.executor = instance.ESAPI.executor();
			local.params = [];
			try {
				local.params.add("/C");
				local.params.add("dir");
				local.result = local.executor.executeSystemCommand(local.cmd, local.params);
				System.out.println( "RESULT: " & local.result );
				assertTrue(local.result.getOutput().length() > 0);
			} catch (java.lang.Exception e) {
				e.printStackTrace();
				fail("");
			}
			try {
				local.exec2 = ioFile.init( local.cmd.getPath() & ";inject.exe" );
				local.result = local.executor.executeSystemCommand(local.exec2, local.params);
				System.out.println( "RESULT: " & local.result );
				fail("");
			} catch (java.lang.Exception e) {
				// expected
			}
			try {
				local.exec2 = ioFile.init( local.cmd.getPath() & "\..\cmd.exe" );
				local.result = local.executor.executeSystemCommand(local.exec2, local.params);
				System.out.println( "RESULT: " & local.result );
				fail("");
			} catch (java.lang.Exception e) {
				// expected
			}
			try {
				local.workdir = ioFile.init( "c:\ridiculous" );
				local.result = local.executor.executeSystemCommand(local.cmd, local.params, local.workdir, local.codec, false, false );
				System.out.println( "RESULT: " & local.result );
				fail("");
			} catch (java.lang.Exception e) {
				// expected
			}
			try {
				local.params.add("&dir");
				local.result = local.executor.executeSystemCommand(local.cmd, local.params);
				System.out.println( "RESULT: " & local.result );
			} catch (java.lang.Exception e) {
				fail("");
			}

			try {
				local.params.set( local.params.size()-1, "c:\autoexec.bat" );
				local.result = local.executor.executeSystemCommand(local.cmd, local.params);
				System.out.println( "RESULT: " & local.result );
			} catch (java.lang.Exception e) {
				fail("");
			}

			try {
				local.params.set( local.params.size()-1, "c:\autoexec.bat c:\config.sys" );
				local.result = local.executor.executeSystemCommand(local.cmd, local.params);
				System.out.println( "RESULT: " & local.result );
			} catch (java.lang.Exception e) {
				fail("");
			}
		</cfscript> 
	</cffunction>


</cfcomponent>

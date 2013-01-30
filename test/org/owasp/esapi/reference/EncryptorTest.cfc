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
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "esapi4cf.org.owasp.esapi.ESAPI" ).init();
	</cfscript>

	<cffunction access="public" returntype="void" name="testHashString" output="false"
	            hint="Test of hash method, of class org.owasp.esapi.Encryptor.">

		<cfscript>
			var local = {};

			System.out.println( "hash" );
			local.encryptor = instance.ESAPI.encryptor();
			local.hash1 = local.encryptor.hashString( "test1", "salt" );
			local.hash2 = local.encryptor.hashString( "test2", "salt" );
			assertFalse( local.hash1.equals( local.hash2 ) );
			local.hash3 = local.encryptor.hashString( "test", "salt1" );
			local.hash4 = local.encryptor.hashString( "test", "salt2" );
			assertFalse( local.hash3.equals( local.hash4 ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncryptString" output="false"
	            hint="Test of encrypt method, of class org.owasp.esapi.Encryptor.">

		<cfscript>
			var local = {};

			System.out.println( "encrypt" );
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = "test123";
			local.ciphertext = local.encryptor.encryptString( local.plaintext );
			local.result = local.encryptor.decryptString( local.ciphertext );
			assertEquals( local.plaintext, local.result );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDecryptString" output="false"
	            hint="Test of decrypt method, of class org.owasp.esapi.Encryptor.">

		<cfscript>
			var local = {};

			System.out.println( "decrypt" );
			local.encryptor = instance.ESAPI.encryptor();
			try {
				local.plaintext = "test123";
				local.ciphertext = local.encryptor.encryptString( local.plaintext );
				assertFalse( local.plaintext.equals( local.ciphertext ) );
				local.result = local.encryptor.decryptString( local.ciphertext );
				assertEquals( local.plaintext, local.result );
			}
			catch(esapi4cf.org.owasp.esapi.errors.EncryptionException e) {
				fail();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSign" output="false"
	            hint="Test of sign method, of class org.owasp.esapi.Encryptor.">

		<cfscript>
			var local = {};

			System.out.println( "sign" );
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = instance.ESAPI.randomizer().getRandomString( 32, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.signature = local.encryptor.sign( local.plaintext );
			assertTrue( local.encryptor.verifySignature( local.signature, local.plaintext ) );
			assertFalse( local.encryptor.verifySignature( local.signature, "ridiculous" ) );
			assertFalse( local.encryptor.verifySignature( "ridiculous", local.plaintext ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testVerifySignature" output="false"
	            hint="Test of verifySignature method, of class org.owasp.esapi.Encryptor.">

		<cfscript>
			var local = {};

			System.out.println( "verifySignature" );
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = instance.ESAPI.randomizer().getRandomString( 32, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.signature = local.encryptor.sign( local.plaintext );
			assertTrue( local.encryptor.verifySignature( local.signature, local.plaintext ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSeal" output="false"
	            hint="Test of seal method, of class org.owasp.esapi.Encryptor.">

		<cfscript>
			var local = {};

			System.out.println( "seal" );
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = instance.ESAPI.randomizer().getRandomString( 32, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.seal = local.encryptor.seal( local.plaintext, getJava( "java.lang.Long" ).init( local.encryptor.getTimeStamp() + 1000 * 60 ) );
			local.encryptor.verifySeal( local.seal );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testVerifySeal" output="false"
	            hint="Test of verifySeal method, of class org.owasp.esapi.Encryptor.">

		<cfscript>
			var local = {};

			System.out.println( "verifySeal" );
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = instance.ESAPI.randomizer().getRandomString( 32, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.seal = local.encryptor.seal( local.plaintext, local.encryptor.getRelativeTimeStamp( 1000 * 60 ) );
			assertTrue( local.encryptor.verifySeal( local.seal ) );
			assertFalse( local.encryptor.verifySeal( "ridiculous" ) );
			assertFalse( local.encryptor.verifySeal( local.encryptor.encryptString( "ridiculous" ) ) );
			assertFalse( local.encryptor.verifySeal( local.encryptor.encryptString( 100 & ":" & "ridiculous" ) ) );
			assertTrue( local.encryptor.verifySeal( local.encryptor.encryptString( getJava( "java.lang.Long" ).MAX_VALUE & ":" & "ridiculous" ) ) );
		</cfscript>

	</cffunction>

</cfcomponent>
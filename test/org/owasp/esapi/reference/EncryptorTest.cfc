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
		variables.ESAPI = createObject( "component", "org.owasp.esapi.ESAPI" ).init();
	</cfscript>
 
	<cffunction access="public" returntype="void" name="testHashString" output="false" hint="Test of hash method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var hash1 = "";
			var hash2 = "";
			var hash3 = "";
			var hash4 = "";
			
			System.out.println( "hash" );
			instance = variables.ESAPI.encryptor();
			hash1 = instance.hashString( "test1", "salt" );
			hash2 = instance.hashString( "test2", "salt" );
			assertFalse( hash1.equals( hash2 ) );
			hash3 = instance.hashString( "test", "salt1" );
			hash4 = instance.hashString( "test", "salt2" );
			assertFalse( hash3.equals( hash4 ) );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncryptString" output="false" hint="Test of encrypt method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var plaintext = "";
			var ciphertext = "";
			var result = "";
			
			System.out.println( "encrypt" );
			instance = variables.ESAPI.encryptor();
			plaintext = "test123";
			ciphertext = instance.encryptString( plaintext );
			result = instance.decryptString( ciphertext );
			assertEquals( plaintext, result );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testDecryptString" output="false" hint="Test of decrypt method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var plaintext = "";
			var ciphertext = "";
			var result = "";
			
			System.out.println( "decrypt" );
			instance = variables.ESAPI.encryptor();
			try {
				plaintext = "test123";
				ciphertext = instance.encryptString( plaintext );
				assertFalse( plaintext.equals( ciphertext ) );
				result = instance.decryptString( ciphertext );
				assertEquals( plaintext, result );
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				fail();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSign" output="false" hint="Test of sign method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var plaintext = "";
			var signature = "";
			
			System.out.println( "sign" );
			instance = variables.ESAPI.encryptor();
			plaintext = variables.ESAPI.randomizer().getRandomString( 32, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			signature = instance.sign(plaintext);
			assertTrue( instance.verifySignature( signature, plaintext ) );
			assertFalse( instance.verifySignature( signature, "ridiculous" ) );
			assertFalse( instance.verifySignature( "ridiculous", plaintext ) );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testVerifySignature" output="false" hint="Test of verifySignature method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var plaintext = "";
			var signature = "";
			
			System.out.println( "verifySignature" );
			instance = variables.ESAPI.encryptor();
			plaintext = variables.ESAPI.randomizer().getRandomString( 32, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			signature = instance.sign( plaintext );
			assertTrue( instance.verifySignature( signature, plaintext ) );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSeal" output="false" hint="Test of seal method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var plaintext = "";
			var seal = "";
			
			System.out.println( "seal" );
			instance = variables.ESAPI.encryptor();
			plaintext = variables.ESAPI.randomizer().getRandomString( 32, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			seal = instance.seal( plaintext, newJava( "java.lang.Long" ).init( instance.getTimeStamp() + 1000 * 60 ) );
			instance.verifySeal( seal );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testVerifySeal" output="false" hint="Test of verifySeal method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var plaintext = "";
			var seal = "";
			
			System.out.println( "verifySeal" );
			instance = variables.ESAPI.encryptor();
			plaintext = variables.ESAPI.randomizer().getRandomString( 32, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			seal = instance.seal( plaintext, instance.getRelativeTimeStamp( 1000 * 60 ) );
			assertTrue( instance.verifySeal( seal ) );
			assertFalse( instance.verifySeal( "ridiculous" ) );
			assertFalse( instance.verifySeal( instance.encryptString( "ridiculous" ) ) );
			assertFalse( instance.verifySeal( instance.encryptString( 100 & ":" & "ridiculous" ) ) );
			assertTrue( instance.verifySeal( instance.encryptString( newJava( "java.lang.Long" ).MAX_VALUE & ":" & "ridiculous" ) ) );
		</cfscript> 
	</cffunction>


</cfcomponent>

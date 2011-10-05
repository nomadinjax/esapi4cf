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
<cfcomponent output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");

		instance.checked = false;
    	instance.unlimited = false;
    </cfscript>
 
	<cffunction access="public" returntype="boolean" name="isUnlimitedStrengthCryptoAvailable" output="false" hint="Check to see if unlimited strength crypto is available. There is an implicit assumption that the JCE jurisdiction policy files are not going to be changing while this given JVM is running.">
		<cfscript>
	        if ( instance.checked == false ) {
	            instance.unlimited = checkCrypto();
	            instance.checked = true;
	        }
	        return instance.unlimited;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="boolean" name="checkCrypto" output="false">
		<cfscript>
	        try {
	            local.keyGen = createObject("java", "javax.crypto.KeyGenerator").getInstance("AES");
	            local.keyGen.init(256);   // Max sym key size is 128 unless unlimited
	                                // strength jurisdiction policy files installed.
	            local.skey = local.keyGen.generateKey();
	            local.raw = local.skey.getEncoded();
	            local.skeySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init(local.raw, "AES");
	            local.cipher = createObject("java", "javax.crypto.Cipher").getInstance("AES/ECB/NoPadding");

	                // This usually will throw InvalidKeyException unless the
	                // unlimited jurisdiction policy files are installed. However,
	                // it can succeed even if it's not a provider chooses to use
	                // an exemption mechanism such as key escrow, key recovery, or
	                // key weakening for this cipher instead.
	            local.cipher.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, local.skeySpec);

	                // Try the encryption on dummy string to make sure it works.
	                // Not using padding so # bytes must be multiple of AES cipher
	                // block size which is 16 bytes. Also, OK not to use UTF-8 here.
	            local.encrypted = local.cipher.doFinal(String.init("1234567890123456").getBytes());
	            assert(!isNull(local.encrypted), "Encryption of test string failed!");
	            local.em = local.cipher.getExemptionMechanism();
	            if ( !isNull(local.em) ) {
	                System.out.println("Cipher uses exemption mechanism " & local.em.getName());
	                return false;   // This is actually an indeterminate case, but
	                                // we can't bank on it at least for this
	                                // (default) provider.
	            }
	        } catch( java.security.InvalidKeyException ikex ) {
	            System.out.println("Invalid key size - unlimited strength crypto NOT installed!");
	            return false;
	        } catch( java.lang.Exception ex ) {
	            System.out.println("Caught unexpected exception: " & ex);
	            ex.printStackTrace(System.out);
	            return false;
	        }
	        return true;
    	</cfscript> 
	</cffunction>


</cfcomponent>

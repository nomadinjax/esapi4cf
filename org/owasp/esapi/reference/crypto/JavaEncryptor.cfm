<cffunction access="private" returntype="binary" name="newByte" outuput="false">
	<cfargument type="numeric" name="len" required="true">
	<cfscript>
		StringBuilder = createObject("java", "java.lang.StringBuilder").init();
		StringBuilder.setLength(arguments.len);
		return StringBuilder.toString().getBytes();
	</cfscript> 
</cffunction>

<cfscript>
	/**
	* Generates a new strongly random secret key and salt that can be
	* copy and pasted in the <b>ESAPI.properties</b> file.
	* 
	* @param args Set first argument to "-print" to display available algorithms on standard output.
	* @throws java.lang.Exception	To cover a multitude of sins, mostly in configuring ESAPI.properties.
	*/
	eol = "<br />";
	writeOutput( "Generating a new secret master key" & eol );
	
	// print out available ciphers
	if ( structKeyExists(url, "print") ) {
		writeOutput( "AVAILABLE ALGORITHMS" & eol );
		
		providers = createObject("java", "java.security.Security").getProviders();
		tm = {};
		// DISCUSS: Note: We go through multiple providers, yet nowhere do I
		//			see where we print out the PROVIDER NAME. Not all providers
		//			will implement the same algorithms and some "partner" with
		//			whom we are exchanging different cryptographic messages may
		//			have _different_ providers in their java.security file. So
		//			it would be useful to know the provider name where each
		//			algorithm is implemented. Might be good to prepend the provider
		//			name to the 'key' with something like "providerName: ". Thoughts?
		for (i = 1; i != arrayLen(providers); i++) {
			// DISCUSS: Print security provider name here???
			// Note: For some odd reason, Provider.keySet() returns
			//		 Set<Object> of the property keys (which are Strings)
			//		 contained in this provider, but Set<String> seems
			//		 more appropriate. But that's why we need the cast below.
			writeOutput("===== Provider " & i & ":" & providers[i].getName() & " ======<ul>");
			it = providers[i].keySet().iterator();
			while (it.hasNext()) {
				key = it.next();
				value = providers[i].getProperty( key );
				tm.put(key, value);
				writeOutput("<li>" & key & " -> " & value & "</li>" );
			}
			writeOutput("</ul>");
		}
		
		keyValueSet = tm.entrySet();
		it = keyValueSet.iterator();
		writeOutput("<hr /><ul>");
		while( it.hasNext() ) {
			entry = it.next();
			key = entry.getKey();
			value = entry.getValue();
			writeOutput( "<li>" & key & " -> " & value & "</li>" );
		}
		writeOutput("</ul>");
	} else {
		// Used to print a similar line to use '-print' even when it was specified.
		writeOutput( "use '?print' to also show available crypto algorithms from all the security providers" & eol );
	}
	
	// setup algorithms -- Each of these have defaults if not set, although
	//					   someone could set them to something invalid. If
	//					   so a suitable exception will be thrown and displayed.
	ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
	encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
	encryptionKeyLength = ESAPI.securityConfiguration().getEncryptionKeyLength();
	randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();
	
	random = createObject("java", "java.security.SecureRandom").getInstance(randomAlgorithm);
	secretKey = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").generateSecretKey(encryptAlgorithm, encryptionKeyLength);
	raw = secretKey.getEncoded();
	salt = newByte(20);	// Or 160-bits; big enough for SHA1, but not SHA-256 or SHA-512.
	random.nextBytes( salt );
	writeOutput( "Copy and paste these lines into your ESAPI.properties" & eol);
	writeOutput( "##==============================================================" & eol);
	writeOutput( "Encryptor.MasterKey=" & ESAPI.encoder().encodeForBase64(raw, false) & eol );
	writeOutput( "Encryptor.MasterSalt=" & ESAPI.encoder().encodeForBase64(salt, false) & eol );
	writeOutput( "##==============================================================" & eol);
</cfscript> 

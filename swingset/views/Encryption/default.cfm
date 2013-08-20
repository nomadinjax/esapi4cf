<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<b><a href="#buildURL('Encryption')#">Tutorial</a></b> | 
<a href="#buildURL('Encryption.lab')#">Lab: Cryptography</a> | 
<a href="#buildURL('Encryption.solution')#">Solution</a> |
<a href="#buildURL('Randomizer.lab')#">Lab: Randomizer</a> |
<a href="#buildURL('Randomizer.solution')#">Solution</a> |
<a href="#buildURL('Integrity.lab')#">Lab: Integrity Seals</a> |
<a href="#buildURL('Integrity.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<h2 align="center">Tutorial</h2>

<h4>Background:</h4>
<p>The failure to encrypt data passes up the guarantees of confidentiality, integrity, and accountability that properly implemented encryption conveys.</p> 

<h4>Consequences:</h4> 
<ul>
<li>Confidentiality: Properly encrypted data channels ensure data confidentiality.</li> 
<li>Integrity: Properly encrypted data channels ensure data integrity.</li> 
<li>Accountability: Properly encrypted data channels ensure accountability.</li> 
</ul>
<h4>Risk:</h4>
<p>Omitting the use of encryption in any program which transfers data over a network of any kind should be considered on par with delivering the data sent to each user on the local networks of both the sender and receiver. 

<br />Worse, this omission allows for the injection of data into a stream of communication between two parties - with no means for the victims to separate valid data from invalid. 

<br /><br />In this day of widespread network attacks and password collection sniffers, it is an unnecessary risk to omit encryption from the design of any system which might benefit from it. 
</p>
<h4>Encryption using ESAPI:</h4>
<p>The Encryptor interface provides a set of methods for performing common encryption, random number, and hashing operations.</p>

<p>Following ESAPI encryption & decryption methods are used in the Encryption lab:</h4>
<ul>
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##decryptString()">java.lang.String decryptString(java.lang.String ciphertext)</a></b> 
         <br /> Decrypts the provided ciphertext string (encrypted with the encrypt method) and returns a plaintext string.</li> 
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##encryptString()">java.lang.String encryptString(java.lang.String plaintext)</a></b> 
         <br /> Encrypts the provided plaintext and returns a ciphertext string.</li> 
</ul>
<p>Encryption & decryption using ESAPI's encryptor interface can be done as follows:</p>
<p class="newsItem">
<code>
encrypted = ESAPI.encryptor().encrypt( decrypted );
<br />decrypted = ESAPI.encryptor().decrypt( encrypted );
</code>
</p>

Following methods from the ESAPI' Encryptor interface are used in the Integrity Seals lab:
<ul>
<li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##getRelativeTimeStamp()">getRelativeTimeStamp(long offset)</a></b> 
          Gets an absolute timestamp representing an offset from the current time to be used by other functions in the library.</li>
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##getTimeStamp()"> long getTimeStamp()</a></b> Gets a timestamp representing the current date and time to be used by other functions in the library.</li> 
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##hashString()">String hashString(java.lang.String plaintext, java.lang.String salt) </a></b>
           Returns a string representation of the hash of the provided plaintext and salt.</li> 
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##seal()">String seal(java.lang.String data, long timestamp) </a></b>
           Creates a seal that binds a set of data and includes an expiration timestamp.</li> 
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##sign()">String sign(java.lang.String data) </a></b>
           Create a digital signature for the provided data and return it in a string.</li> 
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##unseal()">String unseal(java.lang.String seal) </a></b>
           Unseals data (created with the seal method) and throws an exception describing any of the various problems that could exist with a seal, such as an invalid seal format, expired timestamp, or decryption error.</li> 
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##verifySeal()">boolean verifySeal(java.lang.String seal) </a></b>
           Verifies a seal (created with the seal method) and throws an exception describing any of the various problems that could exist with a seal, such as an invalid seal format, expired timestamp, or data mismatch.</li> 
 <li><b><a href="../apiref/org/owasp/esapi/Encryptor.html##verifySignature()">boolean verifySignature(java.lang.String signature, java.lang.String data)</a></b> 
           Verifies a digital signature (created with the sign method) and returns the boolean result.</li> 
</ul>

<h4>Create Seal</h4>
In the secure demo an integrity seal is created for the plain text entered by the user, the seal is set to be valid for 15 seconds by default.
<p class="newsItem">
<code>
seal = ESAPI.encryptor.seal( plaintext, instance.getTimeStamp() + 1000 * Integer.parseInt(timer) );
</code>
</p>
<h4>Verify Seal:</h4>
The call to the following method will return true if the seal is verified within 15 seconds.
<p class="newsItem">
<code>
boolean verified = ESAPI.encryptor.verifySeal( toVerify );
</code>
</p>
<h4>Unseal:</h4>
The call to the following method will unseal it back to the plain text if it is done within 15 seconds.
<p class="newsItem">
<code>
plaintext = ESAPI.encryptor.unseal(sealed); 
</code>
</p>

<p>Insecure randomness errors occur when a function that can produce predictable values is used as a source of randomness in security-sensitive context.</p>
<p>Computers are deterministic machines, and as such are unable to produce true randomness. Pseudo-Random Number Generators (PRNGs) approximate randomness algorithmically, starting with a seed from which subsequent values are calculated.<br /></p>
<p>There are two types of PRNGs: statistical and cryptographic. Statistical PRNGs provide useful statistical properties, but their output is highly predictable and forms an easy to reproduce numeric stream that is unsuitable for use in cases where security depends on generated values being unpredictable. Cryptographic PRNGs address this problem by generating output that is more difficult to predict. For a value to be cryptographically secure, it must be impossible or highly improbable for an attacker to distinguish between it and a truly random value. In general, if a PRNG algorithm is not advertised as being cryptographically secure, then it is probably a statistical PRNG and should not be used in security-sensitive contexts.</p>
<p>Examples:<br />
The following code uses a statistical PRNG to create generate a pseudo-random number.<br />
<p class="newsItem">
	<code>
	int GenerateRandomNumber() { <br />
		<span style="padding-left: 25px;">Random ranGen = new Random();</span><br />
		<span style="padding-left: 25px;">ranGen.setSeed((new Date()).getTime()); </span><br />
		<span style="padding-left: 25px;">return (ranGen.nextInt(400000000)); </span><br />
</span>
		} 
	</pre></code>
</p>
<p>This code uses the Random.nextInt() function to generate "unique" identifiers for the receipt pages it generates. Because Random.nextInt() is a statistical PRNG, it is easy for an attacker to guess the strings it generates. Although the underlying design of the receipt system is also faulty, it would be more secure if it used a random number generator that did not produce predictable receipt identifiers, such as a cryptographic PRNG.</p>
<p>
The Randomizer interface defines a set of methods for creating cryptographically random numbers and strings. Implementers should be sure to use a strong cryptographic implementation, such as the JCE or BouncyCastle. Weak sources of randomness can undermine a wide variety of security mechanisms.
</p>
<p>
ESAPI's Randomizer Interface includes following functions:
</p>
<ul>
	<li> <b><a href="../apiref/org/owasp/esapi/reference/DefaultRandomizer.html##getRandomBoolean()">boolean getRandomBoolean()</a></b> 
	          Returns a random boolean. </li><br />	<br />
	          
	<li> <b><a href="../apiref/org/owasp/esapi/reference/DefaultRandomizer.html##getRandomFilename()">String getRandomFilename(String extension)</a></b> 
	          Returns an unguessable random filename with the specified extension.</li><br /><br />
	
	<li> <b><a href="../apiref/org/owasp/esapi/reference/DefaultRandomizer.html##getRandomGUID()">String getRandomGUID()</a></b>
	          Generates a random GUID. </li><br /><br />
	
	<li> <b><a href="../apiref/org/owasp/esapi/reference/DefaultRandomizer.html##getRandomInteger()">int getRandomInteger(int min, int max)</a></b> 
	          Gets the random integer. </li><br /><br />
	
	<li> <b><a href="../apiref/org/owasp/esapi/reference/DefaultRandomizer.html##getRandomLong()">long getRandomLong()</a></b> 
	          Gets the random long. </li><br /><br />
	
	<li> <b><a href="../apiref/org/owasp/esapi/reference/DefaultRandomizer.html##getRandomReal()">float getRandomReal(float min, float max)</a></b> 
	          Gets the random real. </li><br /><br />
	
	<li> <b><a href="../apiref/org/owasp/esapi/reference/DefaultRandomizer.html##getRandomString()">String getRandomString(int length, char[] characterSet)</a></b> 
          Gets a random string of a desired length and character set. </li>
</ul>

<!--- <h4>ESAPI Encryptor Configuration</h4>
<p>java -classpath ESAPI-2.0-rc4.jar;log4j-
1.2.15.jar org.owasp.esapi.reference.JavaEncryptor</p> --->
</cfoutput>

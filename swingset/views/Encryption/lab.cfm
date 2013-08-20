<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('Encryption')#">Tutorial</a> | 
<b><a href="#buildURL('Encryption.lab')#">Lab: Cryptography</a></b> | 
<a href="#buildURL('Encryption.solution')#">Solution</a> |
<a href="#buildURL('Randomizer.lab')#">Lab: Randomizer</a> |
<a href="#buildURL('Randomizer.solution')#">Solution</a> |
<a href="#buildURL('Integrity.lab')#">Lab: Integrity Seals</a> |
<a href="#buildURL('Integrity.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>

<cfparam name="rc.encrypted" default="">
<cfparam name="rc.decrypted" default="">
<cfscript>
	encrypted = "";
	decrypted = "Encrypt me right now";
	encryptedParam = rc.encrypted;
	decryptedParam = rc.decrypted;	
	
	//TODO encrypt/decrypt the received parameters and re-display them in the appropriate form input fields
</cfscript>

<h2>Encryption Lab</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>
<p>
	Use the ESAPI encryption methods to encrypt and decrypt the text values
	below. <br /> 
	This lab requires the presence of the encryption keys in the ESAPI.properties file. 
<!-- 	<a href="/SwingSet/#buildURL('InitialSetup')#">See Step 4</a> -->
</p>
<table width="100%" border="1">
	<tr>
		<th width="50%">Enter something to encrypt</th>
		<th>Enter something to decrypt</th>
	</tr>
	<tr>
		<td>
			<form action="#buildURL('Encryption.lab')#" method="POST">
				<textarea style="width: 300px; height: 150px" name="decrypted">#decrypted#<!---//TODO : Decrypt the POSTed value ---></textarea>
				<input type="submit" value="encrypt"><br>
			</form>
		</td>
		<td>
			<form action="#buildURL('Encryption.lab')#" method="POST">
				<textarea style="width: 300px; height: 150px" name="encrypted">#encrypted#<!---//TODO : Encrypt the POSTed value ---></textarea>
				<input type="submit" value="decrypt"><br>
			</form>
		</td>
	</tr>
</table>
<p></p>
<p>
Note: The string-based encrypt() and decrypt() methods have been deprecated in favor of the new CipherText-based methods:
</p>
<p class="newsItem">
<code>
plainText = "my string";<br />
ciphertext = application.ESAPI.encryptor().encryptString(plainText);<br />
plainText2 = application.ESAPI.encryptor().decryptString(ciphertext);<br />
</code>
</p>
<p>
This Swingset Application uses ESAPI 2.0 rc4 which doesn't offer easy serialization methods for CipherText objects. <br />
In more recent releases of ESAPI 2.0 (e.g. rc11), the CipherText interface and reference implementation offer the following simple serialization and de-serialization methods which are portable across other ESAPI programming language implementations as well:
</p>
<p class="newsItem">
<code>
asPortableSerializedByteArray()<br />
fromPortableSerializedBytes(bytes)<br />
</code>
</p>
<p>
</p>
</cfoutput>
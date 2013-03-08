<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('Encryption')#">Tutorial</a> | 
<a href="#buildURL('Encryption.lab')#">Lab: Cryptography</a> | 
<b><a href="#buildURL('Encryption.solution')#">Solution</a></b> |
<a href="#buildURL('Randomizer.lab')#">Lab: Randomizer</a> |
<a href="#buildURL('Randomizer.solution')#">Solution</a> |
<a href="#buildURL('Integrity.lab')#">Lab: Integrity Seals</a> |
<a href="#buildURL('Integrity.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>

<cfparam name="rc.decrypted" default="">
<cfparam name="rc.encrypted" default="">

<h2>Encryption Solution</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<p>The values below are encrypted and decrypted with : </p>
<code>
ESAPI().encryptor().encryptString()<br/>
ESAPI().encryptor().decryptString()<br/>
</code>
<br/><br/>
<table width="100%" border="1">
	<tr>
		<th width="50%">Enter something to encrypt</th>
		<th>Enter something to decrypt</th>
	</tr>
	<tr>
		<td>
			<form action="#buildURL('Encryption.solution')#" method="POST">
				<textarea style="width:300px; height:150px" name="decrypted">#rc.decrypted#</textarea>
				<input type="submit" value="encrypt"><br>
			</form>
		</td>
		<td>
			<form action="#buildURL('Encryption.solution')#" method="POST">
				<textarea style="width:300px; height:150px" name="encrypted">#rc.encrypted#</textarea>
				<input type="submit" value="decrypt"><br>
			</form>
		</td>			
	</tr>	
</table>
<p>Encrypted Value: <cfif len(rc.decrypted)>#ESAPI().encryptor().encryptString(rc.decrypted)#</cfif></p>	
<p>Decrypted Value: <cfif len(rc.encrypted)>#ESAPI().encryptor().decryptString(rc.encrypted)#</cfif></p>

</cfoutput>
<cfscript>
	import "org.owasp.esapi.crypto.CryptoHelper";
	import "org.owasp.esapi.util.Utils";

	ESAPI = new org.owasp.esapi.ESAPI();

	/**
	 * Generates a new strongly random secret key and salt that can be
	 * copy and pasted in the ESAPI init of the <b>Application.cfc</b> file.
	 */
    encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
	encryptionKeyLength = ESAPI.securityConfiguration().getEncryptionKeyLength();
	randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();

	random = createObject("java", "java.security.SecureRandom").getInstance(randomAlgorithm);
	secretKey = new CryptoHelper(ESAPI).generateSecretKey(encryptAlgorithm, encryptionKeyLength);
    raw = secretKey.getEncoded();
    salt = new Utils().newByte(160);	// Or 160-bits; big enough for SHA1, but not SHA-256 or SHA-512.
    random.nextBytes( salt );
</cfscript>
<cfoutput><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ESAPI4CF Secret Key Generator</title>
<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
</head>
<body>

<div class="container-fluid">
	<h1>Generating a new secret master key/salt</h1>
	<p>Copy and paste these lines into ESAPI init configuration in Application.cfc##onApplicationStart().</p>
	<pre>
	application.ESAPI = new org.owasp.esapi.ESAPI({
		&quot;Encryptor&quot;: {
			&quot;MasterKey&quot;: &quot;#ESAPI.encoder().encodeForBase64(raw, false)#&quot;,
			&quot;MasterSalt&quot;: &quot;#ESAPI.encoder().encodeForBase64(salt, false)#&quot;
		}
	});
	</pre>
	<div class="alert alert-danger">
		<p>IMPORTANT: Please note that once you set these that changing these keys would invalidate any data that has been encrypted or hashed by ESAPI.</p>
	</div>
</div>

<script src="//code.jquery.com/jquery-2.1.0.min.js"></script>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
</body>
</html></cfoutput>
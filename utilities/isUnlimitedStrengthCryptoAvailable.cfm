<cfscript>
	CryptoPolicy = new test.org.owasp.esapi.reference.crypto.CryptoPolicy();
</cfscript>
<cfoutput><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Unlimited Strength Crypto Available? | ESAPI4CF</title>
<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
</head>
<body>

<div class="container-fluid">
	<h1>Is unlimited strength crypto available?</h1>
	<cfif CryptoPolicy.isUnlimitedStrengthCryptoAvailable()>
        <div class="alert alert-success">Unlimited strength crypto <strong>IS</strong> available.</div>
	<cfelse>
        <div class="alert alert-danger">Unlimited strength crypto is <strong>NOT</strong> available.</div>
    </cfif>
</div>

<script src="//code.jquery.com/jquery-2.1.0.min.js"></script>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
</body>
</html></cfoutput>
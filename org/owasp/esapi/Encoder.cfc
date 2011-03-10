<cfinterface hint="The Encoder interface contains a number of methods for decoding input and encoding output so that it will be safe for a variety of interpreters. To prevent double-encoding, callers should make sure input does not already contain encoded characters by calling canonicalize. Validator implementations should call canonicalize on user input 'before' validating to prevent encoded attacks.">


</cfinterface>

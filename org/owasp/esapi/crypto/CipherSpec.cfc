<!--- /**
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
 */ --->
<cfcomponent displayname="CipherSpec" extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="Specifies all the relevant configuration data needed in constructing and using a {@link javax.crypto.Cipher} except for the encryption key. The 'setters' all return a reference to {@code this} so that they can be strung together. Note: While this is a useful class in it's own right, it should primarily be regarded as an implementation class to use with ESAPI encryption, especially the reference implementation. It is not intended to be used directly by application developers, but rather only by those either extending ESAPI or in the ESAPI reference implementation. Use directly by application code is not recommended or supported.">

	<cfscript>
		instance.serialVersionUID = 20090822;// version, in YYYYMMDD format
		instance.ESAPI = "";

		this.cipher_xform_ = "";
		this.keySize_ = "";// In bits
		this.blockSize_ = 16;// In bytes! I.e., 128 bits!!!
		this.iv_ = toBinary("");

		// Cipher transformation component. Format is ALG/MODE/PADDING
		CipherTransformationComponent = {ALG=newComponent("cfesapi.org.owasp.esapi.crypto.CipherTransformationComponent").init("ALG", 1), MODE=newComponent("cfesapi.org.owasp.esapi.crypto.CipherTransformationComponent").init("MODE", 2), PADDING=newComponent("cfesapi.org.owasp.esapi.crypto.CipherTransformationComponent").init("PADDING", 3)};
	</cfscript>

	<cffunction access="public" returntype="CipherSpec" name="init" output="false"
	            hint="CTOR that explicitly sets everything.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument name="cipher"/>
		<cfargument type="String" name="cipherXform" hint="The cipher transformation"/>
		<cfargument type="numeric" name="keySize" hint="The key size (in bits)."/>
		<cfargument type="numeric" name="blockSize" hint="The block size (in bytes)."/>
		<cfargument type="binary" name="iv" hint="The initialization vector. Null if not applicable."/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			CryptoHelper = newComponent("cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

			if(structKeyExists(arguments, "cipher")) {
				setCipherTransformation(arguments.cipher.getAlgorithm(), true);
				setBlockSize(arguments.cipher.getBlockSize());
				local.iv = arguments.cipher.getIV();
				if(structKeyExists(local, "iv")) {
					setIV(arguments.cipher.getIV());
				}
			}
			else {
				if(structKeyExists(arguments, "cipherXform")) {
					setCipherTransformation(arguments.cipherXform);
				}
				else {
					setCipherTransformation(instance.ESAPI.securityConfiguration().getCipherTransformation());
				}
				if(structKeyExists(arguments, "blockSize")) {
					setBlockSize(arguments.blockSize);
				}
				if(structKeyExists(arguments, "iv")) {
					setIV(arguments.iv);
				}
			}
			if(structKeyExists(arguments, "keySize")) {
				setKeySize(arguments.keySize);
			}
			else {
				setKeySize(instance.ESAPI.securityConfiguration().getEncryptionKeyLength());
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="CipherSpec" name="setCipherTransformation" output="false"
	            hint="Set the cipher transformation for this {@code CipherSpec}. This is only used by the CTOR {@code CipherSpec(Cipher)} and {@code CipherSpec(Cipher, int)}.">
		<cfargument required="true" type="String" name="cipherXform" hint="The cipher transformation string; e.g., 'DESede/CBC/PKCS5Padding'. May not be null or empty."/>
		<cfargument type="boolean" name="fromCipher" default="false" hint="If true, the cipher transformation was set via {@code Cipher.getAlgorithm()} which may only return the actual algorithm. In that case we check and if all 3 parts were not specified, then we specify the parts that were based on 'ECB' as the default cipher mode and 'NoPadding' as the default padding scheme."/>

		<cfset var local = {}/>

		<cfscript>
			if(!newJava("org.owasp.esapi.StringUtilities").notNullOrEmpty(arguments.cipherXform, true)) {// Yes, really want '!' here.
				throwError(newJava("java.lang.IllegalArgumentException").init("Cipher transformation may not be null or empty string (after trimming whitespace)."));
			}
			local.parts = arrayLen(arguments.cipherXform.split("/"));
			assert(iif(!arguments.fromCipher, de(local.parts == 3), de(true)), "Malformed cipherXform (" & arguments.cipherXform & '); must have form: "alg/mode/paddingscheme"');
			if(arguments.fromCipher && (local.parts != 3)) {
				// Indicates cipherXform was set based on Cipher.getAlgorithm()
				// and thus may not be a *complete* cipher transformation.
				if(local.parts == 1) {
					// Only algorithm was given.
					arguments.cipherXform &= "/ECB/NoPadding";
				}
				else if(local.parts == 2) {
					// Only algorithm and mode was given.
					arguments.cipherXform &= "/NoPadding";
				}
				else if(local.parts == 3) {
					// All three parts provided. Do nothing. Could happen if not compiled with
					// assertions enabled.// Do nothing - shown only for completeness.
				}
				else {
					// Should never happen unless Cipher implementation is totally screwed up.
					throwError(newJava("java.lang.IllegalArgumentException").init('Cipher transformation "' & arguments.cipherXform & '" must have form "alg/mode/paddingscheme"'));
				}
			}
			else if(!arguments.fromCipher && local.parts != 3) {
				throwError(newJava("java.lang.IllegalArgumentException").init("Malformed cipherXform (" & arguments.cipherXform & '); must have form: "alg/mode/paddingscheme"'));
			}
			assert(arrayLen(arguments.cipherXform.split("/")) == 3, "Implementation error setCipherTransformation()");
			this.cipher_xform_ = arguments.cipherXform;
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCipherTransformation" output="false"
	            hint="Get the cipher transformation.">

		<cfscript>
			return this.cipher_xform_;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="CipherSpec" name="setKeySize" output="false"
	            hint="Set the key size for this {@code CipherSpec}.">
		<cfargument required="true" type="numeric" name="keySize" hint="The key size, in bits. Must be positive integer."/>

		<cfscript>
			assert(keySize > 0, "keySize must be > 0; keySize=" & keySize);
			this.keySize_ = arguments.keySize;
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getKeySize" output="false"
	            hint="Retrieve the key size, in bits.">

		<cfscript>
			return this.keySize_;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="CipherSpec" name="setBlockSize" output="false"
	            hint="Set the block size for this {@code CipherSpec}.">
		<cfargument required="true" type="numeric" name="blockSize" hint="The block size, in bytes. Must be positive integer."/>

		<cfscript>
			assert(blockSize > 0, "blockSize must be > 0; blockSize=" & blockSize);
			this.blockSize_ = arguments.blockSize;
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getBlockSize" output="false"
	            hint="Retrieve the block size, in bytes.">

		<cfscript>
			return this.blockSize_;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCipherAlgorithm" output="false"
	            hint="Retrieve the cipher algorithm.">

		<cfscript>
			return getFromCipherXform(CipherTransformationComponent.ALG);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCipherMode" output="false"
	            hint="Retrieve the cipher mode.">

		<cfscript>
			return getFromCipherXform(CipherTransformationComponent.MODE);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPaddingScheme" output="false"
	            hint="Retrieve the cipher padding scheme.">

		<cfscript>
			return getFromCipherXform(CipherTransformationComponent.PADDING);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="binary" name="getIV" output="false"
	            hint="Retrieve the initialization vector (IV).">

		<cfscript>
			return this.iv_;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="CipherSpec" name="setIV" output="false"
	            hint="Set the initialization vector (IV).">
		<cfargument required="true" type="binary" name="iv" hint="The byte array to set as the IV. A copy of the IV is saved. This parameter is ignored if the cipher mode does not require an IV."/>

		<cfscript>
			assert(requiresIV() && (structKeyExists(arguments, "iv") && arrayLen(arguments.iv) != 0), "Required IV cannot be null or 0 length");
			// Don't store a reference, but make a copy!
			if(structKeyExists(arguments, "iv")) {// Allow null IV for ECB mode.
				this.iv_ = newByte(arrayLen(arguments.iv));
				CryptoHelper.copyByteArray(arguments.iv, this.iv_);
			}
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="requiresIV" output="false"
	            hint="Return true if the cipher mode requires an IV.">
		<cfset var local = {}/>

		<cfscript>
			local.cm = getCipherMode();

			// Add any other cipher modes supported by JCE but not requiring IV.
			// ECB is the only one I'm aware of that doesn't. Mode is not case
			// sensitive.
			if("ECB" == local.cm) {
				return false;
			}
			return true;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false"
	            hint="Override {@code Object.toString()} to provide something more useful.">
		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init("CipherSpec: ");
			local.sb.append(getCipherTransformation()).append("; keysize= ").append(javaCast("int", getKeySize()));
			local.sb.append(" bits; blocksize= ").append(javaCast("int", getBlockSize())).append(" bytes");
			local.iv = getIV();
			local.ivLen = "";
			if(structKeyExists(local, "iv")) {
				local.ivLen = "" & arrayLen(local.iv);// Convert length to a string
			}
			else {
				local.ivLen = "[No IV present (not set or not required)]";
			}
			local.sb.append("; IV length = ").append(local.ivLen).append(" bytes.");
			return local.sb.toStringESAPI();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="equalsESAPI" output="false">
		<cfargument required="true" name="other"/>

		<cfset var local = {}/>

		<cfscript>
			local.result = false;
			/* throws error - anyway to make this work?
			if(this == other) {
			    return true;
			} */
			if(!isObject(arguments.other)) {
				return false;
			}
			if(isInstanceOf(arguments.other, "cfesapi.org.owasp.esapi.crypto.CipherSpec")) {
				NullSafe = newJava("org.owasp.esapi.util.NullSafe");
				local.that = arguments.other;
				local.result = (local.that.canEqual(this) && NullSafe.equals(this.cipher_xform_, local.that.cipher_xform_) && this.keySize_ == local.that.keySize_ && this.blockSize_ == local.that.blockSize_ && CryptoHelper.arrayCompare(this.iv_, local.that.iv_));// Comparison safe from timing attacks.
			}
			return local.result;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="int" name="hashCodeESAPI" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.sb.append(getCipherTransformation());
			local.sb.append("" & getKeySize());
			local.sb.append("" & getBlockSize());
			local.iv = getIV();
			if(structKeyExists(local, "iv") && local.iv.length > 0) {
				local.ivStr = "";
				try {
					local.ivStr = newJava("java.lang.String").init(local.iv, "UTF-8");
				}
				catch(java.io.UnsupportedEncodingException ex) {
					// Should never happen as UTF-8 encode supported by rt.jar,
					// but it it does, just use default encoding.
					local.ivStr = newJava("java.lang.String").init(local.iv);
				}
				local.sb.append(local.ivStr);
			}
			return local.sb.toStringESAPI().hashCode();
		</cfscript>

	</cffunction>

	<cffunction access="package" returntype="boolean" name="canEqual" output="false"
	            hint="Needed for correct definition of equals for general classes. (Technically not needed for 'final' classes like this class though; this will just allow it to work in the future should we decide to allow sub-classing of this class.) See {@link http://www.artima.com/lejava/articles/equality.html} for full explanation.">
		<cfargument required="true" name="other"/>

		<cfscript>
			return isInstanceOf(arguments.other, "cfesapi.org.owasp.esapi.crypto.CipherSpec");
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="getFromCipherXform" output="false"
	            hint="Split the current cipher transformation and return the requested part. ">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.crypto.CipherTransformationComponent" name="obj" hint="The component of the cipher transformation to return."/>

		<cfset var local = {}/>

		<cfscript>
			local.part = arguments.obj.ordinal();
			local.parts = getCipherTransformation().split("/");
			assert(arrayLen(local.parts) == 3, "Invalid cipher transformation: " & getCipherTransformation());
			return local.parts[local.part];
		</cfscript>

	</cffunction>

</cfcomponent>
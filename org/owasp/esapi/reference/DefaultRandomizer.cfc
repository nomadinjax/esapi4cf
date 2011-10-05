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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Randomizer" output="false">

	<cfscript>
		/* The sr. */
    	instance.secureRandom = "";
	</cfscript>
 
	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Randomizer" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			local.algorithm = instance.ESAPI.securityConfiguration().getRandomAlgorithm();
	        try {
	            instance.secureRandom = createObject("java", "java.security.SecureRandom").getInstance(local.algorithm);
	        } catch (java.security.NoSuchAlgorithmException e) {
	            // Can't throw an exception from the constructor, but this will get it logged and tracked
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Error creating randomizer", "Can't find random algorithm " & local.algorithm, e);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomString" output="false">
		<cfargument type="numeric" name="length" required="true">
		<cfargument type="Array" name="characterSet" required="true">
		<cfscript>
	    	local.sb = createObject("java", "java.lang.StringBuilder").init();
	        for (local.loop = 1; local.loop <= arguments.length; local.loop++) {
	            local.index = instance.secureRandom.nextInt(arrayLen(arguments.characterSet) - 1) + 1;	// we are using Java SecureRandom so account for index difference
	            local.sb.append(arguments.characterSet[local.index]);
	        }
	        local.nonce = local.sb.toString();
	        return local.nonce;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getRandomBoolean" output="false">
		<cfscript>
        	return instance.secureRandom.nextBoolean();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRandomInteger" output="false">
		<cfargument type="numeric" name="min" required="true">
		<cfargument type="numeric" name="max" required="true">
		<cfscript>
        	return instance.secureRandom.nextInt(max - min) + min;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRandomLong" output="false">
		<cfscript>
        	return instance.secureRandom.nextLong();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRandomReal" output="false">
		<cfargument type="numeric" name="min" required="true">
		<cfargument type="numeric" name="max" required="true">
		<cfscript>
	        local.factor = arguments.max - arguments.min;
	        return instance.secureRandom.nextFloat() * local.factor + arguments.min;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomFilename" output="false">
		<cfargument type="String" name="extension" required="true">
		<cfscript>
	        local.fn = getRandomString(12, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS) & "." & arguments.extension;
	        instance.logger.debug(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Generated new random filename: " & local.fn );
	        return local.fn;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomGUID" output="false">
		<cfscript>
    		return createObject("java", "java.util.UUID").randomUUID().toString();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="binary" name="getRandomBytes" output="false">
		<cfargument type="numeric" name="n" required="true">
		<cfscript>
	    	local.result = newByte( arguments.n );
	    	instance.secureRandom.nextBytes(local.result);
	    	return local.result;
    	</cfscript> 
	</cffunction>


</cfcomponent>

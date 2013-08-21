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
<cfcomponent implements="org.owasp.esapi.Randomizer" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Randomizer interface. This implementation builds on the JCE provider to provide a cryptographically strong source of entropy. The specific algorithm used is configurable in ESAPI.properties.">

	<cfscript>
		variables.ESAPI = "";
	
		/** The sr. */
		variables.secureRandom = "";
	
		/** The logger. */
		variables.logger = "";
	</cfscript>
	
	<cffunction access="public" returntype="org.owasp.esapi.Randomizer" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
	
		<cfscript>
			// CF8 requires 'var' at the top
			var algorithm = "";
		
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("Randomizer");
		
			algorithm = variables.ESAPI.securityConfiguration().getRandomAlgorithm();
			try {
				variables.secureRandom = newJava("java.security.SecureRandom").getInstance(algorithm);
			}
			catch(java.security.NoSuchAlgorithmException e) {
				// Can't throw an exception from the constructor, but this will get
				// it logged and tracked
				throwException(createObject("component", "org.owasp.esapi.errors.EncryptionException").init(variables.ESAPI, "Error creating randomizer", "Can't find random algorithm " & algorithm, e));
			}
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getRandomString" output="false">
		<cfargument required="true" type="numeric" name="length"/>
		<cfargument required="true" type="Array" name="characterSet"/>
	
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var loop = "";
			var index = "";
			var nonce = "";
		
			sb = newJava("java.lang.StringBuffer").init();
			for(loop = 1; loop <= arguments.length; loop++) {
				index = variables.secureRandom.nextInt(arrayLen(arguments.characterSet) - 1) + 1;
				sb.append(arguments.characterSet[index]);
			}
			nonce = sb.toString();
			return nonce;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="getRandomBoolean" output="false">
		
		<cfscript>
			return variables.secureRandom.nextBoolean();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getRandomInteger" output="false">
		<cfargument required="true" type="numeric" name="min"/>
		<cfargument required="true" type="numeric" name="max"/>
	
		<cfscript>
			return variables.secureRandom.nextInt(arguments.max - arguments.min) + arguments.min;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getRandomLong" output="false">
		
		<cfscript>
			return variables.secureRandom.nextLong();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getRandomReal" output="false">
		<cfargument required="true" type="numeric" name="min"/>
		<cfargument required="true" type="numeric" name="max"/>
	
		<cfscript>
			var factor = arguments.max - arguments.min;
			return variables.secureRandom.nextFloat() * factor + arguments.min;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getRandomFilename" output="false">
		<cfargument required="true" type="String" name="extension"/>
	
		<cfscript>
			return this.getRandomString(12, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS) & "." & arguments.extension;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getRandomGUID" output="false">
		
		<cfscript>
			return createUUID();
		</cfscript>
		
	</cffunction>
	
</cfcomponent>
<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent implements="esapi4cf.org.owasp.esapi.Randomizer" extends="esapi4cf.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Randomizer interface. This implementation builds on the JCE provider to provide a cryptographically strong source of entropy. The specific algorithm used is configurable in ESAPI.properties.">

	<cfscript>
		instance.ESAPI = "";

		/** The sr. */
		instance.secureRandom = "";

		/** The logger. */
		instance.logger = "";
	</cfscript>

	<cffunction access="public" returntype="esapi4cf.org.owasp.esapi.Randomizer" name="init" output="false">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			var local = {};

			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "Randomizer" );

			local.algorithm = instance.ESAPI.securityConfiguration().getRandomAlgorithm();
			try {
				instance.secureRandom = getJava( "java.security.SecureRandom" ).getInstance( local.algorithm );
			}
			catch(java.security.NoSuchAlgorithmException e) {
				// Can't throw an exception from the constructor, but this will get
				// it logged and tracked
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Error creating randomizer", "Can't find random algorithm " & local.algorithm, e ) );
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRandomString" output="false">
		<cfargument required="true" type="numeric" name="length"/>
		<cfargument required="true" type="Array" name="characterSet"/>

		<cfscript>
			var local = {};

			local.sb = getJava( "java.lang.StringBuffer" ).init();
			for(local.loop = 1; local.loop <= arguments.length; local.loop++) {
				local.index = instance.secureRandom.nextInt( arrayLen( arguments.characterSet ) - 1 ) + 1;
				local.sb.append( arguments.characterSet[local.index] );
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
		<cfargument required="true" type="numeric" name="min"/>
		<cfargument required="true" type="numeric" name="max"/>

		<cfscript>
			return instance.secureRandom.nextInt( arguments.max - arguments.min ) + arguments.min;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRandomLong" output="false">

		<cfscript>
			return instance.secureRandom.nextLong();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRandomReal" output="false">
		<cfargument required="true" type="numeric" name="min"/>
		<cfargument required="true" type="numeric" name="max"/>

		<cfscript>
			var local = {};

			local.factor = arguments.max - arguments.min;
			return instance.secureRandom.nextFloat() * local.factor + arguments.min;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRandomFilename" output="false">
		<cfargument required="true" type="String" name="extension"/>

		<cfscript>
			return this.getRandomString( 12, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS ) & "." & arguments.extension;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRandomGUID" output="false">

		<cfscript>
			return createUUID();
		</cfscript>

	</cffunction>

</cfcomponent>
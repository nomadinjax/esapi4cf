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
<cfcomponent implements="org.owasp.esapi.SecurityConfiguration" output="false" hint="Simple wrapper implementation of {@link SecurityConfiguration}. This allows for easy subclassing and property fixups for unit tests. This has been changed to be concrete instead of abstract so problems caused by changes to the interface will show up here (ie, not abstract not implementing...) instead of versions inheriting from it.">

	<cfscript>
		variables.wrapped = "";
	</cfscript>
 
	<cffunction access="public" returntype="SecurityConfigurationWrapper" name="init" output="false" hint="Constructor wrapping the given configuration.">
		<cfargument required="true" type="org.owasp.esapi.SecurityConfiguration" name="wrapped" hint="The configuration to wrap.">
		<cfscript>
			variables.wrapped = wrapped;

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="org.owasp.esapi.SecurityConfiguration" name="getWrappedSecurityConfiguration" output="false" hint="Access the wrapped configuration.">
		<cfscript>
			return variables.wrapped;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getApplicationName" output="false">
		<cfscript>
			return variables.wrapped.getApplicationName();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getMasterPassword" output="false">
		<cfscript>
			return variables.wrapped.getMasterPassword();
		</cfscript> 
	</cffunction>


	<cffunction access="public" name="getKeystore" output="false">
		<cfscript>
			return variables.wrapped.getKeystore();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="binary" name="getMasterSalt" output="false">
		<cfscript>
			return variables.wrapped.getMasterSalt();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false">
		<cfscript>
			return variables.wrapped.getAllowedFileExtensions();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false">
		<cfscript>
			return variables.wrapped.getAllowedFileUploadSize();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getPasswordParameterName" output="false">
		<cfscript>
			return variables.wrapped.getPasswordParameterName();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getUsernameParameterName" output="false">
		<cfscript>
			return variables.wrapped.getUsernameParameterName();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncryptionAlgorithm" output="false">
		<cfscript>
			return variables.wrapped.getEncryptionAlgorithm();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getHashAlgorithm" output="false">
		<cfscript>
			return variables.wrapped.getHashAlgorithm();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
		<cfscript>
			return variables.wrapped.getCharacterEncoding();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getDigitalSignatureAlgorithm" output="false">
		<cfscript>
			return variables.wrapped.getDigitalSignatureAlgorithm();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomAlgorithm" output="false">
		<cfscript>
			return variables.wrapped.getRandomAlgorithm();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedLoginAttempts" output="false">
		<cfscript>
			return variables.wrapped.getAllowedLoginAttempts();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxOldPasswordHashes" output="false">
		<cfscript>
			return variables.wrapped.getMaxOldPasswordHashes();
		</cfscript> 
	</cffunction>


	<cffunction access="public" name="getQuota" output="false">
		<cfargument required="true" type="String" name="eventName">
		<cfscript>
			return variables.wrapped.getQuota(arguments.eventName);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getResourceDirectory" output="false">
		<cfscript>
			return variables.wrapped.getResourceDirectory();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false">
		<cfargument required="true" type="String" name="dir">
		<cfscript>
			variables.wrapped.setResourceDirectory(arguments.dir);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getResponseContentType" output="false">
		<cfscript>
			return variables.wrapped.getResponseContentType();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false">
		<cfscript>
			return variables.wrapped.getRememberTokenDuration();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false">
		<cfscript>
			return variables.wrapped.getSessionIdleTimeoutLength();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false">
		<cfscript>
			return variables.wrapped.getSessionAbsoluteTimeoutLength();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false">
		<cfscript>
			return variables.wrapped.getLogEncodingRequired();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogDefaultLog4J" output="false">
		<cfscript>
			return variables.wrapped.getLogDefaultLog4J();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false">
		<cfscript>
			return variables.wrapped.getLogLevel();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogFileName" output="false">
		<cfscript>
			return variables.wrapped.getLogFileName();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxLogFileSize" output="false">
		<cfscript>
			return variables.wrapped.getMaxLogFileSize();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false">
		<cfscript>
			return variables.wrapped.getDisableIntrusionDetection();
		</cfscript> 
	</cffunction>


</cfcomponent>

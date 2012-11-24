<cfcomponent implements="cfesapi.org.owasp.esapi.SecurityConfiguration" output="false" hint="Simple wrapper implementation of {@link SecurityConfiguration}. This allows for easy subclassing and property fixups for unit tests. This has been changed to be concrete instead of abstract so problems caused by changes to the interface will show up here (ie, not abstract not implementing...) instead of versions inheriting from it.">

	<cfscript>
		instance.wrapped = "";
	</cfscript>

	<cffunction access="public" returntype="SecurityConfigurationWrapper" name="init" output="false" hint="Constructor wrapping the given configuration.">
		<cfargument required="true" type="SecurityConfiguration" name="wrapped" hint="The configuration to wrap.">
		<cfscript>
			instance.wrapped = wrapped;

			return this;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="getWrappedSecurityConfiguration" output="false" hint="Access the wrapped configuration.">
		<cfscript>
			return instance.wrapped;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getApplicationName" output="false">
		<cfscript>
			return instance.wrapped.getApplicationName();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="Array" name="getMasterPassword" output="false">
		<cfscript>
			return instance.wrapped.getMasterPassword();
		</cfscript>
	</cffunction>

	<cffunction access="public" name="getKeystore" output="false">
		<cfscript>
			return instance.wrapped.getKeystore();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="binary" name="getMasterSalt" output="false">
		<cfscript>
			return instance.wrapped.getMasterSalt();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false">
		<cfscript>
			return instance.wrapped.getAllowedFileExtensions();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false">
		<cfscript>
			return instance.wrapped.getAllowedFileUploadSize();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getPasswordParameterName" output="false">
		<cfscript>
			return instance.wrapped.getPasswordParameterName();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getUsernameParameterName" output="false">
		<cfscript>
			return instance.wrapped.getUsernameParameterName();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getEncryptionAlgorithm" output="false">
		<cfscript>
			return instance.wrapped.getEncryptionAlgorithm();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getHashAlgorithm" output="false">
		<cfscript>
			return instance.wrapped.getHashAlgorithm();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
		<cfscript>
			return instance.wrapped.getCharacterEncoding();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getDigitalSignatureAlgorithm" output="false">
		<cfscript>
			return instance.wrapped.getDigitalSignatureAlgorithm();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getRandomAlgorithm" output="false">
		<cfscript>
			return instance.wrapped.getRandomAlgorithm();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getAllowedLoginAttempts" output="false">
		<cfscript>
			return instance.wrapped.getAllowedLoginAttempts();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getMaxOldPasswordHashes" output="false">
		<cfscript>
			return instance.wrapped.getMaxOldPasswordHashes();
		</cfscript>
	</cffunction>

	<cffunction access="public" name="getQuota" output="false">
		<cfargument required="true" type="String" name="eventName">
		<cfscript>
			return instance.wrapped.getQuota(arguments.eventName);
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getResourceDirectory" output="false">
		<cfscript>
			return instance.wrapped.getResourceDirectory();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false">
		<cfargument required="true" type="String" name="dir">
		<cfscript>
			instance.wrapped.setResourceDirectory(arguments.dir);
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getResponseContentType" output="false">
		<cfscript>
			return instance.wrapped.getResponseContentType();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false">
		<cfscript>
			return instance.wrapped.getRememberTokenDuration();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false">
		<cfscript>
			return instance.wrapped.getSessionIdleTimeoutLength();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false">
		<cfscript>
			return instance.wrapped.getSessionAbsoluteTimeoutLength();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false">
		<cfscript>
			return instance.wrapped.getLogEncodingRequired();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="boolean" name="getLogDefaultLog4J" output="false">
		<cfscript>
			return instance.wrapped.getLogDefaultLog4J();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false">
		<cfscript>
			return instance.wrapped.getLogLevel();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getLogFileName" output="false">
		<cfscript>
			return instance.wrapped.getLogFileName();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getMaxLogFileSize" output="false">
		<cfscript>
			return instance.wrapped.getMaxLogFileSize();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false">
		<cfscript>
			return instance.wrapped.getDisableIntrusionDetection();
		</cfscript>
	</cffunction>

</cfcomponent>

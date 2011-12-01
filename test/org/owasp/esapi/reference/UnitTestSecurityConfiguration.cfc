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
<cfcomponent displayname="UnitTestSecurityConfiguration" extends="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration">

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" name="cfg"/>
	
		<cfscript>
			super.init(arguments.ESAPI, arguments.cfg.getESAPIProperties());
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setApplicationName" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.APPLICATION_NAME, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setLogImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.LOG_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setAuthenticationImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.AUTHENTICATION_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setEncoderImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.ENCODER_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setAccessControlImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.ACCESS_CONTROL_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setEncryptionImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.ENCRYPTION_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setIntrusionDetectionImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.INTRUSION_DETECTION_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setRandomizerImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.RANDOMIZER_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setExecutorImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.EXECUTOR_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setHTTPUtilitiesImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.HTTP_UTILITIES_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setValidationImplementation" output="false">
		<cfargument required="true" type="String" name="v"/>
	
		<cfscript>
			getESAPIProperties().setProperty(this.VALIDATOR_IMPLEMENTATION, arguments.v);
		</cfscript>
		
	</cffunction>
	
</cfcomponent>
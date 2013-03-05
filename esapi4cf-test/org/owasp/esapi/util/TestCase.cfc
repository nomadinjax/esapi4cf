<cfcomponent extends="mxunit.framework.TestCase" output="false">

	<cfscript>
		instance.javaCache = {};

		System = getJava( "java.lang.System" );

		// The following property must be set in order for the tests to find the resources directory
		System.setProperty( "esapi4cf.org.owasp.esapi.resources", "/esapi4cf-test/resources" );
		System.setProperty( "basedir", expandPath("../../../../") );
	</cfscript>

	<cffunction access="private" returntype="void" name="clearUserFile" output="false">
		<!--- clear the User file to prep for tests --->
		<cfset filePath = instance.ESAPI.securityConfiguration().getResourceDirectory() & "users.txt"/>
		<cfset writer = ""/>
		<cfset writer &= "## This is the user file associated with the ESAPI library from http://www.owasp.org" & chr( 13 ) & chr( 10 )/>
		<cfset writer &= "## accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount" & chr( 13 ) & chr( 10 )/>
		<cfset writer &= chr( 13 ) & chr( 10 )/>
		<cffile action="write" file="#expandPath(filePath)#" output="#writer#"/>
	</cffunction>

	<cffunction access="private" name="getJava" output="false">
		<cfargument required="true" type="String" name="classpath"/>

		<cfscript>
			if(!structKeyExists( instance.javaCache, arguments.classpath )) {
				instance.javaCache[arguments.classpath] = createObject( "java", arguments.classpath );
			}

			return instance.javaCache[arguments.classpath];
		</cfscript>

	</cffunction>

	<cffunction access="private" name="getSecurity" output="false">
		<cfargument required="true" type="String" name="type"/>

		<cfscript>
			var local = {};
			local.logger = getJava( "org.owasp.esapi.Logger" );
			// ESAPI 1.4.4
			if(structKeyExists( local.logger, "SECURITY" )) {
				return local.logger.SECURITY;
			}
			// ESAPI 2.0_rc10
			else {
				return local.logger[arguments.type];
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="throwException" output="false">
		<cfargument required="true" name="exception"/>

		<!--- esapi4cf RuntimeExceptions --->
		<cfif isInstanceOf( arguments.exception, "esapi4cf.org.owasp.esapi.util.RuntimeException" )>
			<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
			<!--- esapi4cf Exceptions --->
		<cfelseif isInstanceOf( arguments.exception, "esapi4cf.org.owasp.esapi.util.Exception" )>
			<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getUserMessage()#" detail="#arguments.exception.getLogMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
			<!--- Java Exceptions --->
		<cfelseif isInstanceOf( arguments.exception, "java.lang.Throwable" )>
			<cfthrow object="#arguments.exception#"/>
		<cfelseif isStruct( arguments.exception )>
			<cfthrow attributecollection="#arguments.exception#"/>
		</cfif>
	</cffunction>

	<cffunction access="private" returntype="void" name="cf8_writeDump" output="true">
		<cfargument required="true" name="var"/>
		<cfargument type="boolean" name="abort" default="false"/>

		<cfdump var="#arguments.var#"/>
		<cfif arguments.abort>
			<cfabort/>
		</cfif>
	</cffunction>

	<cffunction access="private" returntype="void" name="cf8_writeLog" output="false"
	            hint="A function equivalent to the &lt;cflog&gt; tag which can be used in &lt;cfscript&gt;.">
		<cfargument required="true" type="String" name="text"/>
		<cfargument type="boolean" name="application"/>
		<cfargument type="String" name="file"/>
		<cfargument type="String" name="log"/>
		<cfargument type="String" name="type"/>

		<cfscript>
			var local = {};

			local.attributeCollection = {};
			if(structKeyExists( arguments, "text" )) {
				local.attributeCollection.text = arguments.text;
			}
			if(structKeyExists( arguments, "application" )) {
				local.attributeCollection.application = arguments.application;
			}
			if(structKeyExists( arguments, "file" )) {
				local.attributeCollection.file = arguments.file;
			}
			if(structKeyExists( arguments, "log" )) {
				local.attributeCollection.log = arguments.log;
			}
			if(structKeyExists( arguments, "type" )) {
				local.attributeCollection.type = arguments.type;
			}
		</cfscript>

		<cflog attributecollection="#local.attributeCollection#"/>
	</cffunction>

</cfcomponent>
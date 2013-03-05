<cfcomponent output="false">

	<cfscript>
		this.VERSION = "1.4.4";	// all CESAPI CFC's will have this

		instance.javaCache = {};

		System = getJava( "java.lang.System" );
	</cfscript>

	<cffunction access="public" name="init" output="false" hint="Default constructor">

		<cfscript>
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="private" name="getJava" output="false">
		<cfargument required="true" type="String" name="classpath"/>

		<cfscript>
			// StringBuffer causes performance issues in Railo
			// will this fix hurt CF8? - if it does, consider using server scope version for logic here
			if (arguments.classpath == "java.lang.StringBuffer") {
				arguments.classpath = "java.lang.StringBuilder";
			}

			if(!structKeyExists( instance.javaCache, arguments.classpath )) {
				instance.javaCache[arguments.classpath] = createObject( "java", arguments.classpath );
			}

			return instance.javaCache[arguments.classpath];
		</cfscript>

	</cffunction>

	<cffunction access="private" name="getSecurity" output="false">
		<cfargument required="true" type="String" name="type"/>

		<cfscript>
			var logger = getJava( "org.owasp.esapi.Logger" );
			// ESAPI 1.4.4
			if(structKeyExists( logger, "SECURITY" )) {
				return logger.SECURITY;
			}
			// ESAPI 2.0_rc10
			else {
				return logger[arguments.type];
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

	<cffunction access="private" returntype="numeric" name="cf8_arrayFind" output="false">
		<cfargument required="true" type="Array" name="array"/>
		<cfargument required="true" name="object"/>

		<cfscript>
			var local = {};

			if(isSimpleValue( arguments.object )) {
				for(local.i = 1; local.i <= arrayLen( arguments.array ); local.i++) {
					if(arguments.object == arguments.array[local.i]) {
						return local.i;
					}
				}
			}
			else {
				for(local.i = 1; local.i <= arrayLen( arguments.array ); local.i++) {
					if(arguments.object.equals( arguments.array[local.i] )) {
						return local.i;
					}
				}
			}
			return 0;
		</cfscript>

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
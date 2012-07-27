<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.ESAPI = "";

		this.key = "";
		this.times = getJava( "java.util.Stack" ).init();
	</cfscript>

	<cffunction access="public" returntype="DefaultIntrusionDetector$Event" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="key"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			this.key = arguments.key;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="increment" output="false">
		<cfargument required="true" type="numeric" name="count"/>
		<cfargument required="true" type="numeric" name="interval"/>

		<cfscript>
			var local = {};
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			local.now = getJava( "java.util.Date" ).init();
			this.times.add( 0, local.now );
			while(this.times.size() > arguments.count)
				instance.times.remove( instance.times.size() - 1 );
			if(this.times.size() == arguments.count) {
				local.past = this.times.get( arguments.count - 1 );
				local.plong = local.past.getTime();
				local.nlong = local.now.getTime();
				if(local.nlong - local.plong < arguments.interval * 1000) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, "Threshold exceeded", "Exceeded threshold for " & this.key ) );
				}
			}
		</cfscript>

	</cffunction>

</cfcomponent>
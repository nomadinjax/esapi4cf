<cfcomponent output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.key = "";
	    instance.times = createObject("java", "java.util.Stack").init();
    </cfscript>

    <cffunction access="public" returntype="Event" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="key" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
       		instance.key = arguments.key;

       		return this;
    	</cfscript>
	</cffunction>

    <cffunction access="public" returntype="void" name="increment" output="false">
		<cfargument type="numeric" name="count" required="true">
		<cfargument type="numeric" name="interval" required="true">
		<cfscript>
	    	if (instance.ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

	        local.now = createObject("java", "java.util.Date").init();
	        instance.times.add( 0, local.now );
	        while ( instance.times.size() > arguments.count ) {
	       		instance.times.remove( instance.times.size()-1 );
	        }
	        if ( instance.times.size() == arguments.count ) {
	            local.past = instance.times.get( arguments.count-1 );
	            local.plong = local.past.getTime();
	            local.nlong = local.now.getTime();
	            if ( local.nlong - local.plong < arguments.interval * 1000 ) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.IntrusionException").init(instance.ESAPI, "Threshold exceeded", "Exceeded threshold for " & instance.key );
	           		throw(type=cfex.getType(), message=cfex.getMessage());
	            }
	        }
    	</cfscript>
	</cffunction>

</cfcomponent>
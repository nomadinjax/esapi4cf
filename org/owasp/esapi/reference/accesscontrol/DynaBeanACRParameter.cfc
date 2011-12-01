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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.reference.accesscontrol.policyloader.PolicyParameters" output="false">

	<cfscript>
		instance.policyProperties = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.reference.accesscontrol.policyloader.PolicyParameters" name="init" output="false">

		<cfscript>
			instance.policyProperties = newJava("org.apache.commons.beanutils.LazyDynaMap").init();

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="any" name="get" output="false">
		<cfargument type="String" name="key" required="true"/>

		<cfscript>
			return instance.policyProperties.get(arguments.key);
		</cfscript>

	</cffunction>

	<!--- getBoolean --->
	<!--- getByte --->
	<!--- getChar --->
	<!--- getInt --->
	<!--- getLong --->
	<!--- getFloat --->
	<!--- getDouble --->
	<!--- getBigDecimal --->
	<!--- getBigInteger --->
	<!--- getDate --->
	<!--- getTime --->

	<cffunction access="public" returntype="String" name="getString" output="false"
	            hint="Convenience method to avoid common casts.">
		<cfargument type="String" name="key" required="true"/>
		<cfargument type="String" name="defaultValue" required="false"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "defaultValue")) {
				local.value = get(arguments.key);
				if(!structKeyExists(local, "value")) {
					return arguments.defaultValue;
				}
				else {
					return get(arguments.key);
				}
			}

			return get(arguments.key);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getStringArray" output="false">
		<cfargument type="String" name="key" required="true"/>

		<cfscript>
			return get(arguments.key);
		</cfscript>

	</cffunction>

	<!--- getObject --->

	<cffunction access="public" returntype="void" name="set" output="false">
		<cfargument type="String" name="key" required="true"/>
		<cfargument type="any" name="value" required="true"/>

		<cfscript>
			instance.policyProperties.set(arguments.key, arguments.value);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="put" output="false">
		<cfargument type="String" name="key" required="true"/>
		<cfargument type="any" name="value" required="true"/>

		<cfscript>
			set(arguments.key, arguments.value);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="lock" output="false"
	            hint="This makes the map itself read only, but the mutability of objects that this map contains is not affected. Specifically, properties cannot be added or removed and the reference cannot be changed to a different object, but this does not change whether the values that the object contains can be changed. ">

		<cfscript>
			instance.policyProperties.setRestricted(true);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.keys = instance.policyProperties.getMap().keySet().iterator();
			local.currentKey = "";
			while(local.keys.hasNext()) {
				local.currentKey = local.keys.next();
				local.sb.append(local.currentKey);
				local.sb.append("=");
				local.sb.append(instance.policyProperties.get(local.currentKey));
				if(local.keys.hasNext()) {
					local.sb.append(",");
				}
			}
			return local.sb.toStringESAPI();
		</cfscript>

	</cffunction>

</cfcomponent>
<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.reference.accesscontrol.policyloader.PolicyParameters" output="false">

	<cfscript>
		instance.policyProperties = "";
	</cfscript>

	<cffunction access="public" returntype="DynaBeanACRParameter" name="init" output="false">
		<cfscript>
			instance.policyProperties = createObject("java", "org.apache.commons.beanutils.LazyDynaMap").init();

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="get" output="false">
		<cfargument type="String" name="key" required="true">
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

	<cffunction access="public" returntype="String" name="getString" output="false" hint="Convenience method to avoid common casts.">
		<cfargument type="String" name="key" required="true">
		<cfargument type="String" name="defaultValue" required="false">
		<cfscript>
			if (structKeyExists(arguments, "defaultValue")) {
				return isNull(get(arguments.key)) ? arguments.defaultValue : get(arguments.key);
			}

			return get(arguments.key);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getStringArray" output="false">
		<cfargument type="String" name="key" required="true">
		<cfscript>
			return get(arguments.key);
		</cfscript>
	</cffunction>

	<!--- getObject --->

	<cffunction access="public" returntype="void" name="set" output="false">
		<cfargument type="String" name="key" required="true">
		<cfargument type="any" name="value" required="true">
		<cfscript>
			instance.policyProperties.set(arguments.key, arguments.value);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="put" output="false">
		<cfargument type="String" name="key" required="true">
		<cfargument type="any" name="value" required="true">
		<cfscript>
			set(arguments.key, arguments.value);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="lock" output="false" hint="This makes the map itself read only, but the mutability of objects that this map contains is not affected. Specifically, properties cannot be added or removed and the reference cannot be changed to a different object, but this does not change whether the values that the object contains can be changed. ">
		<cfscript>
			instance.policyProperties.setRestricted(true);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="toString" output="false">
		<cfscript>
			local.sb = createObject("java", "java.lang.StringBuilder").init();
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
			return local.sb.toString();
		</cfscript>
	</cffunction>


</cfcomponent>

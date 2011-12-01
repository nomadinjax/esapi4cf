<cfcomponent extends="Object" output="false" hint="Wrapper around java.lang.StringBuilder. Also, Adobe ColdFusion 8 has issues with StringBuilder so we use StringBuffer instead for just that version.">

	<cfscript>
		if(listFirst(server.coldFusion.productVersion) <= 8) {
			instance.stringBuilder = newJava("java.lang.StringBuffer");
		}
		else {
			instance.stringBuilder = newJava("java.lang.StringBuilder");
		}
	</cfscript>

	<cffunction access="public" returntype="StringBuilder" name="init" output="false">
		<cfargument type="String" name="str"/>
		<cfargument type="numeric" name="capacity"/>

		<cfscript>
			if(structKeyExists(arguments, "str")) {
				instance.stringBuilder.init(javaCast("string", arguments.str));
			}
			else if(structKeyExists(arguments, "capacity")) {
				instance.stringBuilder.init(javaCast("int", arguments.capacity));
			}
			else {
				instance.stringBuilder.init();
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="StringBuilder" name="append" output="false">
		<cfargument required="true" name="obj"/>

		<cfscript>
			instance.stringBuilder.append(arguments.obj);
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="StringBuilder" name="insertESAPI" output="false">
		<cfargument required="true" type="numeric" name="offset"/>
		<cfargument required="true" name="obj"/>

		<cfscript>
			instance.stringBuilder.insert(javaCast("int", arguments.offset), arguments.obj);
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="length" output="false">

		<cfscript>
			return instance.stringBuilder.length();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLength" output="false">
		<cfargument required="true" type="numeric" name="newLength"/>

		<cfscript>
			instance.stringBuilder.setLength(javaCast("int", arguments.newLength));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="substring" output="false">
		<cfargument required="true" type="numeric" name="start"/>
		<cfargument type="numeric" name="end"/>

		<cfscript>
			if(structKeyExists(arguments, "end")) {
				return instance.stringBuilder.substring(javaCast("int", arguments.start), javaCast("int", arguments.end));
			}
			else {
				return instance.stringBuilder.substring(javaCast("int", arguments.start));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false">

		<cfscript>
			return instance.stringBuilder.toString();
		</cfscript>

	</cffunction>

</cfcomponent>
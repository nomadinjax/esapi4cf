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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.ValidationRule" output="false" hint="Abstract Class">

	<cfscript>
		instance.ESAPI = "";

		instance.typeName = "";
		instance.allowNull = false;
		instance.encoder = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.ValidationRule" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true"/>
		<cfargument type="String" name="typeName" required="true"/>
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="false"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			if(structKeyExists(arguments, "encoder")) {
				setEncoder(arguments.encoder);
			}
			else {
				setEncoder(instance.ESAPI.encoder());
			}
			setTypeName(arguments.typeName);

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAllowNull" output="false">
		<cfargument type="boolean" name="flag" required="true"/>

		<cfscript>
			instance.allowNull = arguments.flag;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getTypeName" output="false">

		<cfscript>
			return instance.typeName;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setTypeName" output="false">
		<cfargument type="String" name="typeName" required="true"/>

		<cfscript>
			instance.typeName = arguments.typeName;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setEncoder" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="true"/>

		<cfscript>
			instance.encoder = arguments.encoder;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertValid" output="false">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>

		<cfscript>
			getValid(arguments.context, arguments.input);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="any" name="getValid" output="false">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false"/>

		<cfset var local = {}/>

		<cfscript>
			local.valid = "";
			try {
				local.valid = getValid(arguments.context, arguments.input);
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				errorList.addError(arguments.context, e);
			}
			return local.valid;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="any" name="getSafe" output="false">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.valid = "";
			try {
				local.valid = getValid(arguments.context, arguments.input);
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return sanitize(arguments.context, arguments.input);
			}
			return local.valid;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="any" name="sanitize" output="false"
	            hint="The method is similar to ValidationRuile.getSafe except that it returns a harmless object that &lt;b&gt;may or may not have any similarity to the original input (in some cases you may not care)&lt;/b&gt;. In most cases this should be the same as the getSafe method only instead of throwing an exception, return some default value.">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidESAPI" output="false">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.valid = false;
			try {
				getValid(arguments.context, arguments.input);
				local.valid = true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				local.valid = false;
			}

			return local.valid;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="whitelist" output="false"
	            hint="Removes characters that aren't in the whitelist from the input String.">
		<cfargument type="String" name="input" required="true" hint="String to be sanitized"/>
		<cfargument type="Array" name="list" required="true" hint="allowed characters"/>

		<cfset var local = {}/>

		<cfscript>
			local.stripped = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			for(local.i = 1; local.i <= len(arguments.input); local.i++) {
				local.c = mid(arguments.input, local.i, 1);
				if(arrayFind(arguments.list, local.c)) {
					local.stripped.append(local.c);
				}
			}
			return local.stripped.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAllowNull" output="false">

		<cfscript>
			return instance.allowNull;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Encoder" name="getEncoder" output="false">

		<cfscript>
			return instance.encoder;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false">

		<cfscript>
			return instance.typeName;
		</cfscript>

	</cffunction>

</cfcomponent>
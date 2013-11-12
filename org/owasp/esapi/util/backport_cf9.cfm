<cffunction access="private" returntype="numeric" name="arrayFind" output="false" hint="CF9 Supplement">
	<cfargument required="true" type="Array" name="array" hint="Name of an array"/>
	<cfargument required="true" name="object" hint="Object to search"/>

	<cfscript>
		return arguments.array.indexOf(arguments.object) + 1;
	</cfscript>
</cffunction>

<cffunction access="private" returntype="boolean" name="isNull" output="false" hint="CF9 Supplement">
	<cfargument required="true" name="obj" hint="Object for which you perform the null check." />

	<!--- CF8 lacks support for isNull() so don't check it --->
	<!--- there has to be a way to "fake" this --->
	<cfreturn false>

</cffunction>

<cffunction access="private" returntype="void" name="throw" output="false" hint="CF9 Supplement">
	<cfargument type="string" name="message">
	<cfargument type="string" name="type">
	<cfargument type="string" name="detail">
	<cfargument type="string" name="errorCode">
	<cfargument type="string" name="extendedInfo">
	<cfargument name="object">

	<cfscript>
		var atts = {};
		if(structKeyExists(arguments, "message")) {
			atts.message = arguments.message;
		}
		if(structKeyExists(arguments, "type")) {
			atts.type = arguments.type;
		}
		if(structKeyExists(arguments, "detail")) {
			atts.detail = arguments.detail;
		}
		if(structKeyExists(arguments, "errorCode")) {
			atts.errorCode = arguments.errorCode;
		}
		if(structKeyExists(arguments, "extendedInfo")) {
			atts.extendedInfo = arguments.extendedInfo;
		}
		if(structKeyExists(arguments, "object")) {
			atts.object = arguments.object;
		}
	</cfscript>
	<cfthrow attributecollection="#atts#"/>
</cffunction>

<cffunction access="private" returntype="void" name="writeDump" output="true" hint="CF9 Supplement: for cfdump">
	<cfargument required="true" name="var"/>
	<cfargument type="string" name="output"/>
	<cfargument type="string" name="format"/>
	<cfargument type="boolean" name="abort" default="false"/>
	<cfargument type="string" name="label"/>
	<cfargument type="boolean" name="metainfo"/>
	<cfargument type="numeric" name="top"/>
	<cfargument type="string" name="show"/>
	<cfargument type="string" name="hide"/>
	<cfargument type="numeric" name="keys"/>
	<cfargument type="boolean" name="expand"/>
	<cfargument type="boolean" name="showUDFs"/>

	<cfscript>
		var atts = {var=arguments.var};
		if(structKeyExists(arguments, "output")) {
			atts.output = arguments.output;
		}
		if(structKeyExists(arguments, "format")) {
			atts.format = arguments.format;
		}
		if(structKeyExists(arguments, "label")) {
			atts.label = arguments.label;
		}
		if(structKeyExists(arguments, "metainfo")) {
			atts.metainfo = arguments.metainfo;
		}
		if(structKeyExists(arguments, "top")) {
			atts.top = arguments.top;
		}
		if(structKeyExists(arguments, "show")) {
			atts.show = arguments.show;
		}
		if(structKeyExists(arguments, "hide")) {
			atts.hide = arguments.hide;
		}
		if(structKeyExists(arguments, "keys")) {
			atts.keys = arguments.keys;
		}
		if(structKeyExists(arguments, "expand")) {
			atts.expand = arguments.expand;
		}
		if(structKeyExists(arguments, "showUDFs")) {
			atts.showUDFs = arguments.showUDFs;
		}
	</cfscript>
	<cfdump attributecollection="#atts#"/>
	<cfif arguments.abort>
		<cfabort/>
	</cfif>
</cffunction>

<cffunction access="private" returntype="void" name="writeLog" output="false" hint="CF9 Supplement: for cflog">
	<cfargument required="true" type="string" name="text"/>
	<cfargument type="string" name="type"/>
	<cfargument type="boolean" name="application"/>
	<cfargument type="string" name="file"/>
	<cfargument type="string" name="log"/>

	<cfscript>
		var atts = {text=arguments.text};
		if(structKeyExists(arguments, "type")) {
			atts.type = arguments.type;
		}
		if(structKeyExists(arguments, "application")) {
			atts.application = arguments.application;
		}
		if(structKeyExists(arguments, "file")) {
			atts.file = arguments.file;
		}
		if(structKeyExists(arguments, "log")) {
			atts.log = arguments.log;
		}
	</cfscript>
	<cflog attributecollection="#atts#"/>
</cffunction>
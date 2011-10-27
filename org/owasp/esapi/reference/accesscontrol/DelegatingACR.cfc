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
<cfcomponent extends="BaseACR" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.delegateMethod = "";
		instance.delegateInstance = "";
	</cfscript>
 
	<cffunction access="public" retunrntype="DelegatingACR" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setPolicyParameters" output="false">
		<cfargument type="any" name="policyParameter" required="true" hint="DynaBeanACRParameter">
		<cfscript>
			local.delegateClassName = arguments.policyParameter.getString("delegateClass", "").trim();
			local.methodName = arguments.policyParameter.getString("delegateMethod", "").trim();
			local.parameterClassNames = arguments.policyParameter.getStringArray("parameterClasses");

			//Convert the classNames into Classes and get the delegate method.
			local.delegateClass = getClassName(local.delegateClassName, "delegate");
			local.parameterClasses = getParameters(local.parameterClassNames);
			try {
				//instance.delegateMethod = local.delegateClass.getMethod(local.methodName, local.parameterClasses);
				instance.delegateMethod = local.methodName;
			} catch (java.lang.SecurityException e) {
				throwError(newJava("java.lang.IllegalArgumentException").init(e.message & ' delegateClass.delegateMethod(parameterClasses): "' & local.delegateClassName & "." & local.methodName & "(" & local.parameterClassNames & ')" must be public.', e));
			} catch (java.lang.NoSuchMethodException e) {
				throwError(newJava("java.lang.IllegalArgumentException").init(e.message & ' delegateClass.delegateMethod(parameterClasses): "' & local.delegateClassName & "." & local.methodName & "(" & local.parameterClassNames & ')" does not exist.', e));
			}

			try {
				instance.delegateInstance = local.delegateClass;
			} catch (java.lang.InstantiationException ex) {
				throwError(newJava("java.lang.IllegalArgumentException").init(' Delegate class "' & local.delegateClassName & '" must be concrete, because method ' & local.delegateClassName & "." & local.methodName & "(" & local.parameterClassNames & ") is not static.", ex));
			} catch (java.lang.IllegalAccessException ex) {
				newJava("java.lang.IllegalArgumentException").init(' Delegate class "' & local.delegateClassName & '" must must have a zero-argument constructor, because method delegateClass.delegateMethod(parameterClasses): "' & local.delegateClassName & "." & local.methodName & "(" & local.parameterClassNames & ')" is not static.', ex);
			}
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="Array" name="getParameters" output="false" hint="Convert an array of fully qualified class names into an array of Class objects">
		<cfargument type="Array" name="parameterClassNames" required="true">
		<cfscript>
			if(arrayLen(arguments.parameterClassNames) EQ 0) {
				return [];
			}
			local.classes = [];
			for (local.i=1; local.i<=arrayLen(arguments.parameterClassNames); local.i++) {
				local.className = arguments.parameterClassNames[local.i];
				local.classes.add(getClassName(local.className, "parameter"));
			}
			return local.classes;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="any" name="getClassName" output="false" hint="Convert a single fully qualified class name into a Class object">
		<cfargument type="String" name="className" required="true">
		<cfargument type="String" name="purpose" required="true">
		<cfscript>
			try {
				if (listFirst(arguments.className, ".") == "cfesapi") {
			        local.theClass = createObject("component", arguments.className).init(ESAPI=instance.ESAPI);
				}
				else {
					local.theClass = newJava(arguments.className).init();
				}
		        return local.theClass;
		    } catch ( Application ex ) {
				throwError(newJava("java.lang.IllegalArgumentException").init(ex.message & " " & arguments.purpose & " Class " & arguments.className & " must be in the classpath", ex));
		    }
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false" hint="Delegates to the method specified in setPolicyParameters">
		<cfargument type="any" name="runtimeParameter" required="true">
		<cfscript>
			//return instance.delegateMethod.invoke(instance.delegateInstance, arguments.runtimeParameter).booleanValue();
			return evaluate("instance.delegateInstance.#instance.delegateMethod#(argumentCollection=arguments.runtimeParameter)");
		</cfscript> 
	</cffunction>


</cfcomponent>

<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent implements="org.owasp.esapi.AccessReferenceMap" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the AccessReferenceMap interface. This implementation generates integers for indirect references.">

	<cfscript>
		variables.ESAPI = "";

		/** The itod (indirect to direct) */
		variables.itod = {};

		/** The dtoi (direct to indirect) */
		variables.dtoi = {};

		variables.count = 1;
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.AccessReferenceMap" name="init" output="false"
	            hint="This AccessReferenceMap implementation uses integers to create a layer of indirection.">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="Array" name="directReferences" hint="Instantiates a new access reference map with a set of direct references."/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.random = variables.ESAPI.randomizer();

			if(structKeyExists(arguments, "directReferences")) {
				this.update(arguments.directReferences);
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="iterator" output="false">

		<cfscript>
			var sorted = createObject("java", "java.util.TreeSet").init(variables.dtoi.keySet());
			return sorted.iterator();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="addDirectReference" output="false">
		<cfargument required="true" name="direct"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var indirect = "";

			if(structKeyExists(variables.dtoi, arguments.direct)) {
				return variables.dtoi[arguments.direct];
			}
			indirect = getUniqueReference();
			variables.itod[indirect] = arguments.direct;
			variables.dtoi[arguments.direct] = indirect;
			return indirect;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="getUniqueReference" output="false"
	            hint="Returns a reference guaranteed to be unique.">

		<cfscript>
			return toString(variables.count++);// returns a string version of the counter
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="removeDirectReference" output="false">
		<cfargument required="true" name="direct"/>

		<cfscript>
			var indirect = "";
			if(structKeyExists(variables.dtoi, arguments.direct)) {
				indirect = variables.dtoi[arguments.direct];
			}
			if(isDefined("indirect") && !isNull(indirect)) {
				variables.itod.remove(indirect);
				variables.dtoi.remove(arguments.direct);
				return indirect;
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="update" output="false">
		<cfargument required="true" type="Array" name="directReferences"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var direct = "";
			var indirect = "";

			var dtoi_old = duplicate(variables.dtoi);
			variables.dtoi.clear();
			variables.itod.clear();

			i = arguments.directReferences.iterator();
			while(i.hasNext()) {
				direct = i.next();
				indirect = "";

				if(structKeyExists(dtoi_old, direct)) {
					// get the old indirect reference
					indirect = dtoi_old[direct];
				}

				// if the old reference is null, then create a new one that doesn't
				// collide with any existing indirect references
				if(!len(indirect)) {
					indirect = getUniqueReference();
				}
				variables.itod[indirect] = direct;
				variables.dtoi[direct] = indirect;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getIndirectReference" output="false">
		<cfargument required="true" name="directReference"/>

		<cfscript>
			if(variables.dtoi.containsKey(arguments.directReference)) {
				return variables.dtoi.get(arguments.directReference);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getDirectReference" output="false">
		<cfargument required="true" type="String" name="indirectReference"/>

		<cfscript>
			var msgParams = [arguments.indirectReference];

			if(variables.itod.containsKey(arguments.indirectReference)) {
				return variables.itod.get(arguments.indirectReference);
			}
			throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("AccessReferenceMap_getDirectReference_invalid_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("AccessReferenceMap_getDirectReference_invalid_logMessage", msgParams)));
		</cfscript>

	</cffunction>

</cfcomponent>
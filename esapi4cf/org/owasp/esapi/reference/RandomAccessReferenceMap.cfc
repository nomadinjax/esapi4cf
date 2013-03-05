<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
--->
<cfcomponent implements="esapi4cf.org.owasp.esapi.AccessReferenceMap" extends="esapi4cf.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the AccessReferenceMap interface. This implementation generates random 6 character alphanumeric strings for indirect references. It is possible to use simple integers as indirect references, but the random string approach provides a certain level of protection from CSRF attacks, because an attacker would have difficulty guessing the indirect reference.">

	<cfscript>
		instance.ESAPI = "";

		/** The itod (indirect to direct) */
		instance.itod = {};

		/** The dtoi (direct to indirect) */
		instance.dtoi = {};

		/** The random. */
		instance.random = "";
	</cfscript>

	<cffunction access="public" returntype="RandomAccessReferenceMap" name="init" output="false" hint="This AccessReferenceMap implementation uses short random strings to create a layer of indirection. Other possible implementations would use simple integers as indirect references.">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI">
		<cfargument type="Array" name="directReferences" hint="Instantiates a new access reference map with a set of direct references.">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.random = instance.ESAPI.randomizer();

			if (structKeyExists(arguments, "directReferences")) {
				this.update(arguments.directReferences);
			}

			return this;
		</cfscript>
	</cffunction>

	<cffunction access="public" name="iterator" output="false">
		<cfscript>
			var local = {};

			local.sorted = getJava("java.util.TreeSet").init(instance.dtoi.keySet());
			return local.sorted.iterator();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="addDirectReference" output="false">
		<cfargument required="true" name="direct">
		<cfscript>
			var local = {};

			if ( instance.dtoi.keySet().contains( arguments.direct ) ) {
				return instance.dtoi.get( arguments.direct );
			}
			local.indirect = getUniqueRandomReference();
			instance.itod.put(local.indirect, arguments.direct);
			instance.dtoi.put(arguments.direct, local.indirect);
			return local.indirect;
		</cfscript>
	</cffunction>

	<cffunction access="private" returntype="String" name="getUniqueRandomReference" output="true" hint="Create a new random reference that is guaranteed to be unique.">
		<cfscript>
			var local = {};

			local.candidate = "";
			do {
				local.candidate = instance.random.getRandomString(6, getJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			} while (structKeyExists(instance.itod, local.candidate));
			return local.candidate;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="removeDirectReference" output="false">
		<cfargument required="true" name="direct">
		<cfscript>
			var local = {};

			if (instance.dtoi.containsKey(arguments.direct)) {
				local.indirect = instance.dtoi.get(arguments.direct);
			}
			if ( structKeyExists(local, "indirect") ) {
				instance.itod.remove(local.indirect);
				instance.dtoi.remove(arguments.direct);
				return local.indirect;
			}
			return "";
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="update" output="false">
		<cfargument required="true" type="Array" name="directReferences">
		<cfscript>
			var local = {};

			local.dtoi_old = duplicate(instance.dtoi);
			instance.dtoi.clear();
			instance.itod.clear();

			local.i = arguments.directReferences.iterator();
			while (local.i.hasNext()) {
				local.direct = local.i.next();

				if (local.dtoi_old.containsKey(local.direct)) {
					// get the old indirect reference
					local.indirect = local.dtoi_old.get(local.direct);
				}

				// if the old reference is null, then create a new one that doesn't
				// collide with any existing indirect references
				if (!structKeyExists(local, "indirect")) {
					local.indirect = getUniqueRandomReference();
				}

				instance.itod.put(local.indirect, local.direct);
				instance.dtoi.put(local.direct, local.indirect);
				structDelete(local, "indirect");
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getIndirectReference" output="false">
		<cfargument required="true" name="directReference">
		<cfscript>
			if (instance.dtoi.containsKey(arguments.directReference)) {
				return instance.dtoi.get(arguments.directReference);
			}
			return "";
		</cfscript>
	</cffunction>

	<cffunction access="public" name="getDirectReference" output="false">
		<cfargument required="true" type="String" name="indirectReference">
		<cfscript>
			if (instance.itod.containsKey(arguments.indirectReference)) {
				return instance.itod.get(arguments.indirectReference);
			}
			throwException(createObject("component", "esapi4cf.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access denied", "Request for invalid indirect reference: " & arguments.indirectReference));
		</cfscript>
	</cffunction>

</cfcomponent>

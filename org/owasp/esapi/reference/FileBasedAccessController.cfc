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
<cfcomponent implements="org.owasp.esapi.AccessController" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the AccessController interface. This reference implementation uses a simple model for specifying a set of access control rules. Many organizations will want to create their own implementation of the methods provided in the AccessController interface. This reference implementation uses a simple scheme for specifying the rules. The first step is to create a namespace for the resources being accessed. For files and URL's, this is easy as they already have a namespace. Be extremely careful about canonicalizing when relying on information from the user in an access control decision. For functions, data, and services, you will have to come up with your own namespace for the resources being accessed. You might simply define a flat namespace with a list of category names. For example, you might specify 'FunctionA', 'FunctionB', and 'FunctionC'. Once you've defined your namespace, you have to work out the rules that govern access to the different parts of the namespace. This implementation allows you to attach a simple access control list (ACL) to any part of the namespace tree. The ACL lists a set of roles that are either allowed or denied access to a part of the tree. You specify these rules in a textfile with a simple format. There is a single configuration file supporting each of the five methods in the AccessController interface. These files are located in the ESAPI resources directory as specified when the JVM was started. The use of a default deny rule is STRONGLY recommended.">

	<cfscript>
		variables.ESAPI = "";

		/** The url map. */
		variables.urlMap = {};

		/** The function map. */
		variables.functionMap = {};

		/** The data map. */
		variables.dataMap = {};

		/** The file map. */
		variables.fileMap = {};

		/** The service map. */
		variables.serviceMap = {};

		/** A rule containing "deny". */
		variables.deny = createObject("component", "FileBasedAccessController$Rule").init();

		/** The logger. */
		variables.logger = "";
	</cfscript>

	<cffunction access="public" returntype="FileBasedAccessController" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("AccessController");

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForURL" output="false">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>
			try {
				assertAuthorizedForURL(arguments.url);
				return true;
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFunction" output="false">
		<cfargument required="true" type="String" name="functionName"/>

		<cfscript>
			try {
				assertAuthorizedForFunction(arguments.functionName);
				return true;
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForData" output="false">
		<cfargument required="true" type="String" name="action"/>
		<cfargument name="data"/>

		<cfscript>
			try {
				assertAuthorizedForData(argumentCollection=arguments);
				return true;
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFile" output="false">
		<cfargument required="true" type="String" name="filepath"/>

		<cfscript>
			try {
				assertAuthorizedForFile(arguments.filepath);
				return true;
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForService" output="false">
		<cfargument required="true" type="String" name="serviceName"/>

		<cfscript>
			try {
				assertAuthorizedForService(arguments.serviceName);
				return true;
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForURL" output="false">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>
			if(isNull(variables.urlMap) || variables.urlMap.isEmpty()) {
				variables.urlMap = loadRules("URLAccessRules.txt");
			}
			if(!matchRuleByPath(variables.urlMap, arguments.url)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Not authorized for URL", "Not authorized for URL: " & arguments.url));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForFunction" output="false">
		<cfargument required="true" type="String" name="functionName"/>

		<cfscript>
			if(isNull(variables.functionMap) || variables.functionMap.isEmpty()) {
				variables.functionMap = loadRules("FunctionAccessRules.txt");
			}
			if(!matchRuleByPath(variables.functionMap, arguments.functionName)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Not authorized for function", "Not authorized for function: " & arguments.functionName));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForData" output="false">
		<cfargument required="true" type="String" name="action"/>
		<cfargument name="data"/>

		<cfscript>
			if(isNull(variables.dataMap) || variables.dataMap.isEmpty()) {
				variables.dataMap = loadDataRules("DataAccessRules.txt");
			}

			if(structKeyExists(arguments, "data")) {
				if(!matchRuleByAction(variables.dataMap, arguments.data, arguments.action)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Not authorized for data", "Not authorized for data: " & arguments.data.getClass().getName()));
				}
			}
			else if(!matchRuleByPath(variables.dataMap, arguments.action)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Not authorized for function", "Not authorized for data: " & arguments.action));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForFile" output="false">
		<cfargument required="true" type="String" name="filepath"/>

		<cfscript>
			if(isNull(variables.fileMap) || variables.fileMap.isEmpty()) {
				variables.fileMap = loadRules("FileAccessRules.txt");
			}
			if(!matchRuleByPath(variables.fileMap, arguments.filepath.replaceAll("\\", "/"))) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Not authorized for file", "Not authorized for file: " & arguments.filepath));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForService" output="false">
		<cfargument required="true" type="String" name="serviceName"/>

		<cfscript>
			if(isNull(variables.serviceMap) || variables.serviceMap.isEmpty()) {
				variables.serviceMap = loadRules("ServiceAccessRules.txt");
			}
			if(!matchRuleByPath(variables.serviceMap, arguments.serviceName)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Not authorized for service", "Not authorized for service: " & arguments.serviceName));
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="matchRuleByPath" output="false"
	            hint="Checks to see if the current user has access to the specified data, File, Object, etc. If the User has access, as specified by the map parameter, this method returns true.  If the User does not have access or an exception is thrown, false is returned.">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" type="String" name="path" hint="the path of the requested File, URL, Object, etc."/>

		<cfscript>
			// get users roles
			var user = variables.ESAPI.authenticator().getCurrentUser();
			var roles = user.getRoles();
			// search for the first rule that matches the path and rules
			var rule = searchForRuleByPath(arguments.map, roles, arguments.path);
			return rule.allow;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="matchRuleByAction" output="false"
	            hint="Checks to see if the current user has access to the specified Class and action. If the User has access, as specified by the map parameter, this method returns true. If the User does not have access or an exception is thrown, false is returned.">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" name="clazz" hint="the Class being requested for access"/>
		<cfargument required="true" type="String" name="action" hint="the action the User has asked to perform"/>

		<cfscript>
			// get users roles
			var user = variables.ESAPI.authenticator().getCurrentUser();
			var roles = user.getRoles();
			// search for the first rule that matches the path and rules
			var rule = searchForRuleByAction(arguments.map, roles, arguments.clazz, arguments.action);
			return isObject(rule);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="FileBasedAccessController$Rule" name="searchForRuleByPath" output="false"
	            hint="Search for rule. Four mapping rules are used in order: - exact match, e.g. /access/login - longest path prefix match, beginning / and ending /*, e.g. /access/* or /* - extension match, beginning *., e.g. *.css - default servlet, specified by the single character pattern /">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" type="Array" name="roles" hint="the roles of the User being checked for access"/>
		<cfargument required="true" type="String" name="path" hint="the File, URL, Object, etc. being checked for access"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var part = "";
			var extension = "";
			var extIndex = "";
			var rule = "";
			var slash = "";

			var canonical = "";
			try {
				canonical = variables.ESAPI.encoder().canonicalize(arguments.path);
			}
			catch(org.owasp.esapi.errors.EncodingException e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Failed to canonicalize input: " & arguments.path);
			}

			part = canonical;
			if(part == "") {
				part = "";
			}

			while(part.endsWith("/")) {
				part = part.substring(0, part.length() - 1);
			}

			if(part.indexOf("..") != -1) {
				throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init("Attempt to manipulate access control path", "Attempt to manipulate access control path: " & arguments.path));
			}

			// extract extension if any
			extension = "";
			extIndex = part.lastIndexOf(".");
			if(extIndex != -1) {
				extension = part.substring(extIndex + 1);
			}

			rule = "";
			// Check for exact match - ignore any ending slash
			if(structKeyExists(arguments.map, part)) {
				rule = arguments.map[part];
			}

			// Check for ending with /*
			if(!isObject(rule)) {
				if(structKeyExists(arguments.map, part & "/*")) {
					rule = arguments.map[part & "/*"];
				}
			}

			// Check for matching extension rule *.ext
			if(!isObject(rule)) {
				if(structKeyExists(arguments.map, "*." & extension)) {
					rule = arguments.map["*." & extension];
				}
			}

			// if rule found and user's roles match rules' roles, return the rule
			if(isDefined("rule") && !isNull(rule) && isStruct(rule) && overlapByRoles(rule.roles, arguments.roles)) {
				return rule;
			}

			// rule hasn't been found - if there are no more parts, return a deny
			slash = part.lastIndexOf("/");
			if(slash == -1) {
				return variables.deny;
			}

			// if there are more parts, strip off the last part and recurse
			part = part.substring(0, part.lastIndexOf("/"));

			// return default deny
			if(part.length() <= 1) {
				return variables.deny;
			}

			return searchForRuleByPath(arguments.map, arguments.roles, part);
		</cfscript>

	</cffunction>

	<cffunction access="private" name="searchForRuleByAction" output="false" hint="Search for rule. Searches the specified access map to see if any of the roles specified have access to perform the specified action on the specified Class.">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" type="Array" name="roles" hint="the roles used to determine access level"/>
		<cfargument required="true" name="clazz" hint="the Class being requested for access"/>
		<cfargument required="true" type="String" name="action" hint="the action the User has asked to perform"/>

		<cfscript>
			var rule = "";
			// Check for exact match - ignore any ending slash
			if(structKeyExists(arguments.map, arguments.clazz.getClass().getName())) {
				rule = arguments.map.get(arguments.clazz.getClass().getName());
			}
			if((isDefined("rule") && !isNull(rule)) && isStruct(rule) && (overlapByAction(rule.actions, arguments.action)) && (overlapByRoles(rule.roles, arguments.roles))) {
				return rule;
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="overlapByRoles" output="false"
	            hint="Return true if there is overlap between the two sets.  This method merely checks to see if ruleRoles contains any of the roles listed in userRoles.">
		<cfargument required="true" type="Array" name="ruleRoles" hint="the rule roles"/>
		<cfargument required="true" type="Array" name="userRoles" hint="the user roles"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var role = "";

			if(arguments.ruleRoles.contains("any")) {
				return true;
			}
			i = arguments.userRoles.iterator();
			while(i.hasNext()) {
				role = i.next();
				if(arguments.ruleRoles.contains(role)) {
					return true;
				}
			}
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="overlapByAction" output="false"
	            hint="This method merely checks to see if ruleActions contains the action requested.">
		<cfargument required="true" type="Array" name="ruleActions" hint="actions listed for a rule"/>
		<cfargument required="true" type="String" name="action" hint="the action requested that will be searched for in ruleActions"/>

		<cfscript>
			if(arguments.ruleActions.contains(arguments.action))
				return true;
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Array" name="validateRoles" output="false"
	            hint="Checks that the roles passed in contain only letters, numbers, and underscores.  Also checks that roles are no more than 10 characters long.  If a role does not pass validation, it is not included in the list of roles returned by this method.  A log warning is also generated for any invalid roles.">
		<cfargument required="true" type="Array" name="roles" hint="roles to validate according to criteria started above"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var ret = "";
			var x = "";
			var canonical = "";

			ret = [];
			for(x = 1; x <= arrayLen(arguments.roles); x++) {
				canonical = "";
				try {
					canonical = variables.ESAPI.encoder().canonicalize(trim(arguments.roles[x]));
				}
				catch(org.owasp.esapi.errors.EncodingException e) {
					variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Failed to canonicalize role " & trim(arguments.roles[x]), e);
				}
				if(!variables.ESAPI.validator().isValidInput("Validating user roles in FileBasedAccessController", canonical, "^[a-zA-Z0-9_]{0,10}$", 200, false))
					variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Role: " & trim(arguments.roles[x]) & " is invalid, so was not added to the list of roles for this Rule.");
				else
					ret.add(canonical.trim());
			}
			return ret;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Struct" name="loadRules" output="false"
	            hint="Loads access rules by storing them in a hashmap.  This method begins reading the File specified by the ruleset parameter, ignoring any lines that begin with '##' characters as comments.  Sections of the access rules file are split by the pipe character ('|').  The method loads all paths, replacing '\' characters with '/' for uniformity then loads the list of comma separated roles. The roles are validated to be sure they are within a length and character set, specified in the validateRoles(String) method.  Then the permissions are stored for each item in the rules list. If the word 'allow' appears on the line, the specified roles are granted access to the data - otherwise, they will be denied access. Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored.">
		<cfargument required="true" type="String" name="ruleset" hint="the name of the data that contains access rules"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var line = "";
			var rule = "";
			var parts = "";
			var roles = "";
			var x = "";
			var action = "";

			var map = {};
			var ins = "";
			try {
				ins = newJava("java.io.FileInputStream").init(newJava("java.io.File").init(variables.ESAPI.securityConfiguration().getResourceDirectory(), arguments.ruleset));
				line = variables.ESAPI.validator().safeReadLine(ins, 500);
				while(isDefined("line") && !isNull(line)) {
					if(line.length() > 0 && line.charAt(0) != chr(35)) {
						rule = createObject("component", "FileBasedAccessController$Rule").init();
						parts = line.split("\|");
						// fix Windows paths
						rule.path = parts[1].trim().replaceAll("\\", "/");

						roles = commaSplit(parts[2].trim().toLowerCase());
						roles = validateRoles(roles);
						for(x = 1; x <= arrayLen(roles); x++)
							rule.roles.add(trim(roles[x]));

						action = parts[3].trim();
						rule.allow = action.equalsIgnoreCase("allow");
						if(map.containsKey(rule.path)) {
							variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Problem in access control file. Duplicate rule ignored: " & rule);
						}
						else {
							map.put(rule.path, rule);
						}
					}
					line = variables.ESAPI.validator().safeReadLine(ins, 500);
				}
			}
			catch(java.lang.Exception e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Problem in access control file : " & arguments.ruleset, e);
			}
			try {
				if(isObject(ins)) {
					ins.close();
				}
			}
			catch(java.io.IOException e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Failure closing access control file : " & arguments.ruleset, e);
			}

			return map;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Struct" name="loadDataRules" output="false"
	            hint="Loads access rules by storing them in a hashmap.  This method begins reading the File specified by the ruleset parameter, ignoring any lines that begin with '##' characters as comments.  Sections of the access rules file are split by the pipe character ('|').  The method then loads all Classes, loads the list of comma separated roles, then the list of comma separated actions. The roles are validated to be sure they are within a length and character set, specified in the validateRoles(String) method. Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored.">
		<cfargument required="true" type="String" name="ruleset" hint="the name of the data that contains access rules"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var line = "";
			var rule = "";
			var parts = "";
			var roles = "";
			var x = "";
			var action = "";

			var map = {};
			var ins = "";

			try {
				ins = newJava("java.io.FileInputStream").init(newJava("java.io.File").init(variables.ESAPI.securityConfiguration().getResourceDirectory(), arguments.ruleset));
				line = variables.ESAPI.validator().safeReadLine(ins, 500);
				while(isDefined("line") && !isNull(line)) {
					if(line.length() > 0 && line.charAt(0) != chr(35)) {
						rule = createObject("component", "FileBasedAccessController$Rule").init();
						parts = line.split("\|");
						rule.clazz = parts[1].trim();

						roles = commaSplit(parts[2].trim().toLowerCase());
						roles = validateRoles(roles);
						for(x = 1; x <= arrayLen(roles); x++)
							rule.roles.add(trim(roles[x]));

						action = commaSplit(parts[3].trim().toLowerCase());
						for(x = 1; x <= arrayLen(action); x++)
							rule.actions.add(trim(action[x]));

						if(map.containsKey(rule.path)) {
							variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Problem in access control file. Duplicate rule ignored: " & rule.toStringData());
						}
						else {
							map.put(rule.clazz, rule);
						}
					}
					line = variables.ESAPI.validator().safeReadLine(ins, 500);
				}
			}
			catch(java.lang.Exception e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Problem in access control file : " & arguments.ruleset, e);
			}

			try {
				if(isObject(ins)) {
					ins.close();
				}
			}
			catch(java.io.IOException e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Failure closing access control file : " & arguments.ruleset, e);
			}

			return map;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Array" name="commaSplit" output="false"
	            hint="This method splits a String by the ',' and returns the result as a List.">
		<cfargument required="true" type="String" name="input" hint="the String to split by ','"/>

		<cfscript>
			var array = arguments.input.split(",");
			return array;
		</cfscript>

	</cffunction>

</cfcomponent>
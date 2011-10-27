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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false">

	<cfscript>
		instance.ESAPI = "";

		/* The url map. */
		instance.urlMap = {};

		/* The function map. */
		instance.functionMap = {};

		/* The data map. */
		instance.dataMap = {};

		/* The file map. */
		instance.fileMap = {};

		/* The service map. */
		instance.serviceMap = {};

		/* A rule containing "deny". */
		instance.deny = new Rule();

		/* The logger. */
		instance.logger = "";
	</cfscript>
 
	<cffunction access="public" returntype="FileBasedACRs" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("FileBasedACRs");

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorizedForURL" output="false" hint="Check if URL is authorized.">
		<cfargument type="String" name="url" required="true" hint="The URL tested for authorization">
		<cfscript>
			if (!isStruct(instance.urlMap) || instance.urlMap.isEmpty()) {
				instance.urlMap = loadRules("URLAccessRules.txt");
			}
			return matchRule(instance.urlMap, arguments.url);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorizedForFunction" output="false">
		<cfargument type="String" name="functionName" required="true">
		<cfscript>
	    	if (!isStruct(instance.functionMap) || instance.functionMap.isEmpty()) {
				instance.functionMap = loadRules("FunctionAccessRules.txt");
			}
			return matchRule(instance.functionMap, arguments.functionName);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorizedForData" output="false">
		<cfargument type="String" name="action" required="true">
		<cfargument type="any" name="data" required="true">
		<cfscript>
	    	if (!isStruct(instance.dataMap) || instance.dataMap.isEmpty()) {
				instance.dataMap = loadDataRules("DataAccessRules.txt");
	    	}
	    	return matchClassRule(instance.dataMap, arguments.data, arguments.action);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorizedForFile" output="false">
		<cfargument type="String" name="filepath" required="true">
		<cfscript>
			if (!isStruct(instance.fileMap) || instance.fileMap.isEmpty()) {
				instance.fileMap = loadRules("FileAccessRules.txt");
			}
			return matchRule(instance.fileMap, arguments.filepath.replaceAll("\\\\","/"));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorizedForService" output="false">
		<cfargument type="String" name="serviceName" required="true">
		<cfscript>
			if (!isStruct(instance.serviceMap) || instance.serviceMap.isEmpty()) {
				instance.serviceMap = loadRules("ServiceAccessRules.txt");
			}
			return matchRule(instance.serviceMap, arguments.serviceName);
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="boolean" name="matchRule" output="false" hint="Checks to see if the current user has access to the specified data, File, Object, etc. If the User has access, as specified by the map parameter, this method returns true.  If the User does not have access or an exception is thrown, false is returned.">
		<cfargument type="Struct" name="map" required="true" hint="the map containing access rules">
		<cfargument type="String" name="path" required="true" hint="the path of the requested File, URL, Object, etc.">
		<cfscript>
			// get users roles
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.roles = local.user.getRoles();
			// search for the first rule that matches the path and rules
			local.rule = searchForRule(arguments.map, local.roles, arguments.path);
			return local.rule.allow;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="boolean" name="matchClassRule" output="false" hint="Checks to see if the current user has access to the specified Class and action. If the User has access, as specified by the map parameter, this method returns true. If the User does not have access or an exception is thrown, false is returned.">
		<cfargument type="Struct" name="map" required="true" hint="the map containing access rules">
		<cfargument type="any" name="clazz" required="true" hint="the Class being requested for access">
		<cfargument type="String" name="action" required="true" hint="the action the User has asked to perform">
		<cfscript>
			// get users roles
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.roles = local.user.getRoles();
			// search for the first rule that matches the path and rules
			local.rule = searchForClassRule(arguments.map, local.roles, arguments.clazz, arguments.action);
			return !isNull(local.rule);
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="Rule" name="searchForRule" output="false" hint="Search for rule. Four mapping rules are used in order: - exact match, e.g. /access/login - longest path prefix match, beginning / and ending /*, e.g. /access/* or /* - extension match, beginning *., e.g. *.css - default servlet, specified by the single character pattern /">
		<cfargument type="Struct" name="map" required="true" hint="the map containing access rules">
		<cfargument type="Array" name="roles" required="true" hint="the roles of the User being checked for access">
		<cfargument type="String" name="path" required="true" hint="the File, URL, Object, etc. being checked for access">
		<cfscript>
			local.canonical = instance.ESAPI.encoder().canonicalize(arguments.path);

			local.part = local.canonical;
	        if ( local.part == "" ) {
	            local.part = "";
	        }

			while (local.part.endsWith("/")) {
				local.part = local.part.substring(0, local.part.length() - 1);
			}

			if (local.part.indexOf("..") != -1) {
				throwError(new cfesapi.org.owasp.esapi.errors.IntrusionException(instance.ESAPI, "Attempt to manipulate access control path", "Attempt to manipulate access control path: " & arguments.path ));
			}

			// extract extension if any
			local.extension = "";
			local.extIndex = local.part.lastIndexOf(".");
			if (local.extIndex != -1) {
				local.extension = local.part.substring(local.extIndex + 1);
			}

			// Check for exact match - ignore any ending slash
			if (structKeyExists(arguments.map, local.part)) {
				local.rule = arguments.map.get(local.part);
			}

			// Check for ending with /*
			if (isNull(local.rule)) {
				if (structKeyExists(arguments.map, local.part & "/*")) {
					local.rule = arguments.map.get(local.part & "/*");/* this comment fixes IDE syntax error */
				}
			}

			// Check for matching extension rule *.ext
			if (isNull(local.rule)) {
				if (structKeyExists(arguments.map, "*." & local.extension)) {
					local.rule = arguments.map.get("*." & local.extension);
				}
			}

			// if rule found and user's roles match rules' roles, return the rule
			if (!isNull(local.rule) && overlap(local.rule.roles, arguments.roles)) {
				return local.rule;
			}

			// rule hasn't been found - if there are no more parts, return a deny
			local.slash = local.part.lastIndexOf('/');
			if ( local.slash == -1 ) {
				return instance.deny;
			}

			// if there are more parts, strip off the last part and recurse
			local.part = local.part.substring(0, local.part.lastIndexOf('/'));

			// return default deny
			if (local.part.length() <= 1) {
				return instance.deny;
			}

			return searchForRule(arguments.map, arguments.roles, local.part);
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="any" name="searchForClassRule" output="false" hint="Rule: Search for rule. Searches the specified access map to see if any of the roles specified have access to perform the specified action on the specified Class.">
		<cfargument type="Struct" name="map" required="true" hint="the map containing access rules">
		<cfargument type="Array" name="roles" required="true" hint="the roles used to determine access level">
		<cfargument type="any" name="clazz" required="true" hint="the Class being requested for access">
		<cfargument type="String" name="action" required="true" hint="the action the User has asked to perform">
		<cfscript>
			// Check for exact match - ignore any ending slash
			if (structKeyExists(arguments.map, arguments.clazz.getClass().getName())) {
				local.rule = arguments.map.get(arguments.clazz.getClass().getName());
			}
			if( ( !isNull(local.rule) ) && ( overlapClass(local.rule.actions, arguments.action) ) && ( overlap(local.rule.roles, arguments.roles) )){
				return local.rule;
			}
			return;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="boolean" name="overlap" output="false" hint="Return true if there is overlap between the two sets.  This method merely checks to see if  ruleRoles contains any of the roles listed in userRoles.">
		<cfargument type="Array" name="ruleRoles" required="true" hint="the rule roles">
		<cfargument type="Array" name="userRoles" required="true" hint="the user roles">
		<cfscript>
			if (arguments.ruleRoles.contains("any")) {
				return true;
			}
			for (local.i=1; local.i<=arrayLen(arguments.userRoles); local.i++) {
				local.role = arguments.userRoles[local.i];
				if (arguments.ruleRoles.contains(local.role)) {
					return true;
				}
			}
			return false;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="boolean" name="overlapClass" output="false" hint="This method merely checks to see if ruleActions contains the action requested.">
		<cfargument type="Array" name="ruleActions" required="true" hint="actions listed for a rule">
		<cfargument type="String" name="action" required="true" hint="the action requested that will be searched for in ruleActions">
		<cfscript>
			if( arguments.ruleActions.contains(arguments.action) ) {
				return true;
			}
			return false;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="Array" name="validateRoles" output="false" hint="Checks that the roles passed in contain only letters, numbers, and underscores.  Also checks that roles are no more than 10 characters long.  If a role does not pass validation, it is not included in the list of roles returned by this method.  A log warning is also generated for any invalid roles.">
		<cfargument type="Array" name="roles" required="true" hint="roles to validate according to criteria started above">
		<cfscript>
			local.ret = [];
			for(local.x = 1; local.x <= arrayLen(arguments.roles); local.x++){
				local.canonical = instance.ESAPI.encoder().canonicalize(arguments.roles[local.x].trim());

				if(!instance.ESAPI.validator().isValidInput("Validating user roles in FileBasedAccessController", local.canonical, "RoleName", 20, false)) {
					instance.logger.warning( newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Role: " & arguments.roles[local.x].trim() & " is invalid, so was not added to the list of roles for this Rule.");
				} else {
					local.ret.add(local.canonical.trim());
				}
			}
			return local.ret;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="Struct" name="loadRules" output="false" hint="Loads access rules by storing them in a hashmap.  This method begins reading the File specified by the ruleset parameter, ignoring any lines that begin with '##' characters as comments.  Sections of the access rules file are split by the pipe character ('|').  The method loads all paths, replacing '\' characters with '/' for uniformity then loads the list of comma separated roles. The roles are validated to be sure they are within a length and character set, specified in the validateRoles(String) method.  Then the permissions are stored for each item in the rules list. If the word 'allow' appears on the line, the specified roles are granted access to the data - otherwise, they will be denied access. Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored.">
		<cfargument type="String" name="ruleset" required="true" hint="the name of the data that contains access rules">
		<cfscript>
			local.ruleset = "fbac-policies/" & arguments.ruleset;
			local.map = {};
			local.is = "";

			try {
				local.is = instance.ESAPI.securityConfiguration().getResourceStream(local.ruleset);
				local.line = instance.ESAPI.validator().safeReadLine(local.is, 500);
				while (!isNull(local.line)) {
					if (local.line.length() > 0 && local.line.charAt(0) != chr(35)) {
						local.rule = new Rule();
						local.parts = local.line.split("\|");
						// fix Windows paths
						local.rule.path = local.parts[1].trim().replaceAll("\\\\", "/");

						local.roles = local.parts[2].trim().toLowerCase().split(",");
						local.roles = validateRoles(local.roles);
						for(local.x = 1; local.x <= arrayLen(local.roles); local.x++) {
							local.rule.roles.add(local.roles[local.x].trim());
						}
						local.action = local.parts[3].trim();
						local.rule.allow = local.action.equalsIgnoreCase("allow");
						if (local.map.containsKey(local.rule.path)) {
							instance.logger.warning( newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem in access control file. Duplicate rule ignored: " & local.rule);
						} else {
							local.map.put(local.rule.path, local.rule);
						}
					}
					local.line = instance.ESAPI.validator().safeReadLine(local.is, 500);
				}
			} catch (java.io.FileNotFoundException e) {
				instance.logger.warning( newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem in access control file: " & local.ruleset, e );
			} finally {
				try {
					if (isObject(local.is)) {
						local.is.close();
					}
				} catch (java.io.IOException e) {
					instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Failure closing access control file: " & local.ruleset, e);
				}
			}
			return local.map;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="Struct" name="loadDataRules" output="false" hint="Loads access rules by storing them in a hashmap.  This method begins reading the File specified by the ruleset parameter, ignoring any lines that begin with '##' characters as comments.  Sections of the access rules file are split by the pipe character ('|').  The method then loads all Classes, loads the list of comma separated roles, then the list of comma separated actions.  The roles are validated to be sure they are within a length and character set, specified in the validateRoles(String) method. Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored.">
		<cfargument type="String" name="ruleset" required="true" hint="the name of the data that contains access rules">
		<cfscript>
			local.ruleset = "fbac-policies/" & arguments.ruleset;
			local.map = {};
			local.is = "";

			try {
				local.is = instance.ESAPI.securityConfiguration().getResourceStream(local.ruleset);
				local.line = instance.ESAPI.validator().safeReadLine(local.is, 500);
				while (!isNull(local.line)) {
					if (local.line.length() > 0 && local.line.charAt(0) != chr(35)) {
						local.rule = new Rule();
						local.parts = local.line.split("\|");
						local.rule.path = local.parts[1].trim();
						local.rule.clazz = newJava(local.rule.path);

						local.roles = local.parts[2].trim().toLowerCase().split(",");
						local.roles = validateRoles(local.roles);
						for(local.x = 1; local.x <= arrayLen(local.roles); local.x++) {
							local.rule.roles.add(local.roles[local.x].trim());
						}
						local.action = local.parts[3].trim().toLowerCase().split(",");
						for(local.x = 1; local.x <= arrayLen(local.action); local.x++) {
							local.rule.actions.add(local.action[local.x].trim());
						}
						if (local.map.containsKey(local.rule.path)) {
							logger.warning( newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem in access control file. Duplicate rule ignored: " & local.rule);
						} else {
							local.map.put(local.rule.path, local.rule);
						}
					}
					local.line = instance.ESAPI.validator().safeReadLine(local.is, 500);
				}
			} catch (java.io.FileNotFoundException e) {
				instance.logger.warning( newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem in access control file : " & local.ruleset, e );
			} finally {
				try {
					if (isObject(local.is)) {
						local.is.close();
					}
				} catch (java.io.IOException e) {
					instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Failure closing access control file : " & local.ruleset, e);
				}
			}
			return local.map;
		</cfscript> 
	</cffunction>

	<!--- commaSplit --->

</cfcomponent>

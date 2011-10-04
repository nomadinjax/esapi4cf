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
<cfscript>
	currentUser = ESAPI().authenticator().getCurrentUser();
</cfscript> 
<header>
	<h1>
		CFESAPI FileBasedAuthenticator Demo App 
	</h1>
	<cfif currentUser.isLoggedIn()>
		<cfoutput>
			<p>
				<!--- typically you would use getScreenName() but in the default users.txt we are not saving this field --->
				Welcome, 
				<strong>
					#encodeForHTML(currentUser.getAccountName())#
				</strong>
				. You are logged in with these roles: 
				<strong>
					#encodeForHTML(arrayToList(currentUser.getRoles()))#
				</strong>
				. 
			</p>
		</cfoutput>
	</cfif>
	<nav>
		<ul>
			<li>
				<a href="/cfesapi/demo/fba/index.cfm">
					Home 
				</a>
			</li>
			<li>
				<!--- this is intentional - profile at root displays Anonymous, profile in members for authenticated users --->
				<cfif currentUser.isAnonymous()>
					<a href="/cfesapi/demo/fba/myProfile.cfm">
						About Me
					</a>
				<cfelse>
					<a href="/cfesapi/demo/fba/members/myProfile.cfm">
						My Profile 
					</a>
				</cfif>
			</li>
			<!--- <cfif currentUser.isInRole("user")> --->
			<li>
				<a href="/cfesapi/demo/fba/members/index.cfm">
					Members 
				</a>
			</li>
			<!--- </cfif> --->
			<!--- <cfif currentUser.isInRole("admin")> --->
			<li>
				<a href="/cfesapi/demo/fba/admin/index.cfm">
					Administration 
				</a>
			</li>
			<!--- </cfif> --->
			<cfif currentUser.isLoggedIn()>
				<li>
					<a href="?logout">
						Logout 
					</a>
				</li>
			</cfif>
		</ul>
	</nav>
</header>

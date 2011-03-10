<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.HttpServletResponse" output="false">

	<cfscript>
		/* The cookies. */
		instance.cookies = [];

		/* The header names. */
		instance.headerNames = [];

		/* The header values. */
		instance.headerValues = [];

		/* The status. */
		instance.status = 200;

		instance.body = createObject("java", "java.lang.StringBuffer").init();

		//instance.contentType = "text/html; charset=ISO-8895-1";
	</cfscript>

	<cffunction access="public" returntype="MockHttpServletResponse" name="init" output="false">
		<cfscript>
			return this;
		</cfscript>
	</cffunction>

	<!--- getBody --->

	<cffunction access="public" returntype="void" name="addCookie" output="false">
		<cfargument type="any" name="cookie" required="true" hint="javax.servlet.http.Cookie">
		<cfscript>
			instance.cookies.add(arguments.cookie);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getCookies" output="false" hint="Gets the cookies.">
		<cfscript>
			return duplicate(instance.cookies);
		</cfscript>
	</cffunction>

	<!--- getCookie --->
	<!--- addDateHeader --->

	<cffunction access="public" returntype="void" name="addHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfscript>
			instance.headerNames.add(arguments.name);
			instance.headerValues.add(arguments.value);
		</cfscript>
	</cffunction>

	<!--- addIntHeader --->

	<cffunction access="public" returntype="boolean" name="containsHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			return instance.headerNames.contains(arguments.name);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getHeader" output="false" hint="Gets the header.">
		<cfargument type="String" name="name" required="true" hint="the name">
		<cfscript>
			local.index = instance.headerNames.indexOf(arguments.name);
			if (local.index != -1) {
				return instance.headerValues.get(local.index);
			}
			return "";
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false" hint="Gets the header names.">
		<cfscript>
			return instance.headerNames;
		</cfscript>
	</cffunction>

	<!--- encodeRedirectURL --->
	<!--- encodeURL --->
	<!--- sendError --->

	<cffunction access="public" returntype="void" name="sendRedirect" output="false">
		<cfargument type="String" name="location" required="true">
		<cfscript>
			instance.status = createObject("java", "javax.servlet.http.HttpServletResponse").SC_MOVED_PERMANENTLY;
			instance.body = createObject("java", "java.lang.StringBuffer").init( "Redirect to " & arguments.location );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setDateHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="numeric" name="date" required="true">
		<cfscript>
			instance.headerNames.add(arguments.name);
			instance.headerValues.add("" & arguments.date);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfscript>
			instance.headerNames.add(arguments.name);
			instance.headerValues.add(arguments.value);
		</cfscript>
	</cffunction>

	<!--- setIntHeader --->
	<!--- setStatus --->
	<!--- getStatus --->
	<!--- flushBuffer --->
	<!--- getBufferSize --->

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
		<cfscript>
			return "UTF-8";
		</cfscript>
	</cffunction>

	<!--- getContentType --->
	<!--- getLocale --->
	<!--- getOutputStream --->
	<!--- getWriter --->
	<!--- isCommitted --->
	<!--- reset --->
	<!--- resetBuffer --->
	<!--- setBody --->
	<!--- setBufferSize --->
	<!--- setCharacterEncoding --->
	<!--- setContentLength --->
	<!--- setContentType --->
	<!--- setLocale --->
	<!--- dump --->

</cfcomponent>

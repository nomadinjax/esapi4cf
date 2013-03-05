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
<!---  implements="esapi4cf.org.owasp.esapi.HttpServletResponse" --->
<cfcomponent extends="esapi4cf.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		/** The cookies. */
		instance.cookies = [];

		/** The header names. */
		instance.headerNames = [];

		/** The header values. */
		instance.headerValues = [];

		/** The status. */
		instance.status = 200;
	</cfscript>

	<cffunction access="public" returntype="void" name="addCookie" output="false">
		<cfargument required="true" name="cookie"/>

		<cfscript>
			instance.cookies.add( arguments.cookie );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getCookies" output="false"
	            hint="Gets the cookies.">

		<cfscript>
			return instance.cookies;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getCookie" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.i = instance.cookies.iterator();
			while(local.i.hasNext()) {
				local.c = local.i.next();
				if(local.c.getName() == arguments.name) {
					return local.c;
				}
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addDateHeader" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="Date" name="date"/>

		<cfscript>
			instance.headerNames.add( arguments.name );
			instance.headerValues.add( "" & arguments.date );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addHeader" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			instance.headerNames.add( arguments.name );
			instance.headerValues.add( arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addIntHeader" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="numeric" name="value"/>

		<cfscript>
			instance.headerNames.add( arguments.name );
			instance.headerValues.add( "" & arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="containsHeader" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.headerNames.contains( name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHeader" output="false"
	            hint="Gets the header.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.index = instance.headerNames.indexOf( arguments.name );
			if(local.index != -1) {
				return instance.headerValues.get( local.index );
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false"
	            hint="Gets the header names.">

		<cfscript>
			return instance.headerNames;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeRedirectURL" output="false">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>

			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeURL" output="false">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="sendError" output="false">
		<cfargument required="true" type="numeric" name="sc"/>
		<cfargument required="false" type="String" name="msg"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="sendRedirect" output="false">
		<cfargument required="true" type="String" name="location"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setDateHeader" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="Date" name="date"/>

		<cfscript>
			instance.headerNames.add( arguments.name );
			instance.headerValues.add( "" & arguments.date );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setHeader" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			instance.headerNames.add( arguments.name );
			instance.headerValues.add( arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setIntHeader" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="numeric" name="value"/>

		<cfscript>
			instance.headerNames.add( arguments.name );
			instance.headerValues.add( "" & arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setStatus" output="false">
		<cfargument required="true" type="numeric" name="sc"/>
		<cfargument required="false" type="String" name="sm"/>

		<cfscript>
			instance.status = arguments.sc;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="int" name="getStatus" output="false"
	            hint="Gets the status.">

		<cfscript>
			return instance.status;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="flushBuffer" output="false">

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getBufferSize" output="false">

		<cfscript>

			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">

		<cfscript>

			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContentType" output="false">

		<cfscript>

			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false">

		<cfscript>

			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getOutputStream" output="false">

		<cfscript>

			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getWriter" output="false">

		<cfscript>

			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isCommitted" output="false">

		<cfscript>

			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="reset" output="false">

	</cffunction>

	<cffunction access="public" returntype="void" name="resetBuffer" output="false">

	</cffunction>

	<cffunction access="public" returntype="void" name="setBufferSize" output="false">
		<cfargument required="true" type="numeric" name="size"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false">
		<cfargument required="true" type="String" name="charset"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContentLength" output="false">
		<cfargument required="true" type="numeric" name="len"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContentType" output="false">
		<cfargument required="true" type="String" name="type"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLocaleData" output="false">
		<cfargument required="true" name="loc"/>

	</cffunction>

</cfcomponent>
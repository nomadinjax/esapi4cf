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
<cfsetting showdebugoutput="false" requesttimeout="180" />
<cfinvoke component="mxunit.runner.DirectoryTestSuite" method="run" directory="#expandPath('.')#" componentpath="cfesapi.test" recurse="true" returnvariable="results" />
<cfoutput>
	#results.getResultsOutput('html')# 
</cfoutput>

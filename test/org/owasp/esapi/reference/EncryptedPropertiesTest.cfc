<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();
	</cfscript>
	
</cfcomponent>
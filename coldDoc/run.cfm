<!---
Let's generate our default HTML documentation on myself: 
 --->
<cfscript>
	colddoc = createObject("component", "ColdDoc").init();

	strategy = createObject("component", "colddoc.strategy.api.HTMLAPIStrategy").init(expandPath("../apiref"), "ESAPI v2.0");
	colddoc.setStrategy(strategy);

	colddoc.generate(expandPath("/org"), "org");
</cfscript>

<h1>Done!</h1>

<a href="../apiref">Documentation</a>

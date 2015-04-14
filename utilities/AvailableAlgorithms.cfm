<cfscript>
writeOutput( "AVAILABLE ALGORITHMS"  & eol);

providers = createObject("java", "java.security.Security").getProviders();
tm = {};
// DISCUSS: Note: We go through multiple providers, yet nowhere do I
//			see where we print out the PROVIDER NAME. Not all providers
//			will implement the same algorithms and some "partner" with
//			whom we are exchanging different cryptographic messages may
//			have _different_ providers in their java.security file. So
//			it would be useful to know the provider name where each
//			algorithm is implemented. Might be good to prepend the provider
//			name to the 'key' with something like "providerName: ". Thoughts?
for (i = 1; i != arrayLen(providers); i++) {
	// DISCUSS: Print security provider name here???
		// Note: For some odd reason, Provider.keySet() returns
		//		 Set<Object> of the property keys (which are Strings)
		//		 contained in this provider, but Set<String> seems
		//		 more appropriate. But that's why we need the cast below.
    writeOutput("===== Provider " & i & ":" & providers[i].getName() & " ======" & eol);
	it = providers[i].keySet().iterator();
	while (it.hasNext()) {
		key = it.next();
        value = providers[i].getProperty( key );
        tm.put(key, value);
        writeOutput("&nbsp;&nbsp;&nbsp;&nbsp;   " & key & " -> "& value  & eol);
	}
}

keyValueSet = tm.entrySet();
it = keyValueSet.iterator();
while( it.hasNext() ) {
	entry = it.next();
	key = entry.getKey();
	value = entry.getValue();
	writeOutput( "   " & key & " -> "& value  & eol);
}
</cfscript>
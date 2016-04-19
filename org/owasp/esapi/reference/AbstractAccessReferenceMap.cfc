/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
import "org.owasp.esapi.errors.AccessControlException";

/**
 * Abstract Implementation of the AccessReferenceMap that is backed by ConcurrentHashMaps to
 * provide a thread-safe implementation of the AccessReferenceMap. Implementations of this
 * abstract class should implement the #getUniqueReference() method.
 */
component implements="org.owasp.esapi.AccessReferenceMap" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";

	/** The Indirect to Direct Map */
	variables.itod = {};
	/** The Direct to Indirect Map */
	variables.dtoi = {};

   /**
    * Instantiates a new access reference map with the specified size allotment
    * and initializes the map with the passed in references. Note that if you pass
    * in an initialSize that is less than the size of the passed in set, the map will
    * need to be resized while it is being loaded with the references so it is
    * best practice to verify that the size being passed in is always larger than
    * the size of the set that is being passed in.
    *
    * @param directReferences
    *          The references to initialize the access reference map
    * @param initialSize
    *          The initial size to set the map to.
    *
    * @deprecated This constructor internally calls the abstract method
    *	{@link #getUniqueReference()}. Since this is a constructor, any
    *	subclass that implements getUniqueReference() has not had it's
    *	own constructor run. This leads to strange bugs because subclass
    *	internal state is initializaed after calls to getUniqueReference()
    *	have already happened. If this constructor is desired in a
    *	subclass, consider running {@link #update(Set)} in the subclass
    *	constructor instead.
    */
	public AbstractAccessReferenceMap function init(required org.owasp.esapi.ESAPI ESAPI, array directReferences, numeric initialSize) {
		variables.ESAPI = arguments.ESAPI;

		if (structKeyExists(arguments, "directReferences") && structKeyExists(arguments, "initialSize")) {
			variables.itod = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arguments.initialSize);
			variables.dtoi = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arguments.initialSize);
			update(arguments.directReferences);
		}
		else if (structKeyExists(arguments, "directReferences")) {
			variables.itod = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arrayLen(arguments.directReferences));
			variables.dtoi = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arrayLen(arguments.directReferences));
			update(arguments.directReferences);
		}
		else if (structKeyExists(arguments, "initialSize")) {
			variables.itod = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arguments.initialSize);
			variables.dtoi = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arguments.initialSize);
		}
		return this;
	}

   /**
    * Returns a Unique Reference Key to be associated with a new directReference being
    * inserted into the AccessReferenceMap.
    *
    * @return Reference Identifier
    */
   private function getUniqueReference() {};

   public function iterator() {
      var sorted = createObject("java", "java.util.TreeSet").init(variables.dtoi.keySet());
      return sorted.iterator();
   }

   public function addDirectReference(required direct) {
      if (structKeyExists(variables.dtoi, arguments.direct)) {
         return variables.dtoi[arguments.direct];
      }
      var indirect = getUniqueReference();
      variables.itod.put(indirect, arguments.direct);
      variables.dtoi.put(arguments.direct, indirect);
      return indirect;
   }

	public function removeDirectReference(required direct) {
		var indirect = variables.dtoi.get(arguments.direct);
		if (isNull(indirect)) return;
		variables.itod.remove(indirect);
		variables.dtoi.remove(arguments.direct);
		return indirect;
	}

	public void function update(required array directReferences) {
		var new_dtoi = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arrayLen(arguments.directReferences));
		var new_itod = createObject("java", "java.util.concurrent.ConcurrentHashMap").init(arrayLen(arguments.directReferences));

		for ( var o in arguments.directReferences ) {
			var indirect = "";
			if (structKeyExists(variables.dtoi, o)) {
				indirect = variables.dtoi[o];
			}

			if (!len(indirect)) {
				indirect = getUniqueReference();
			}
			new_dtoi.put( o, indirect );
			new_itod.put( indirect, o );
		}
		variables.dtoi = new_dtoi;
		variables.itod = new_itod;
	}

   public function getIndirectReference(required directReference) {
      return variables.dtoi.get(arguments.directReference);
   }

   public function getDirectReference(required indirectReference) {
      if (variables.itod.containsKey(arguments.indirectReference) ) {
         try {
            return variables.itod.get(arguments.indirectReference);
         }
         catch (ClassCastException e) {
            throws(new AccessControlException(variables.ESAPI, "Access denied.", "Request for incorrect type reference: " & arguments.indirectReference));
         }
      }
      throws(new AccessControlException(variables.ESAPI, "Access denied", "Request for invalid indirect reference: " & arguments.indirectReference));
   }

}

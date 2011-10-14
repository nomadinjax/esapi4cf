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
/**
 * This interface represents the abstract notion of a principal, which can be used to represent any entity, such as an individual, a corporation, and a login id.
 */
interface {

	/**
	 * Compares this principal to the specified object. Returns true if the object passed in matches the principal represented by the implementation of this interface.
	 *
	 * @param another principal to compare with.
	 *
	 * @return true if the principal passed in is the same as that encapsulated by this principal, and false otherwise.
	 */
	
	public boolean function isEquals(required another);
	
	/**
	 * Returns the name of this principal.
	 *
	 * @return the name of this principal.
	 */
	
	public String function getName();
	
	/**
	 * Returns a hashcode for this principal.
	 *
	 * @return a hashcode for this principal.
	 */
	
	public numeric function hashCode();
	
	/**
	 * Returns a string representation of this principal.
	 *
	 * @return a string representation of this principal.
	 */
	
	public String function toString();
	
}
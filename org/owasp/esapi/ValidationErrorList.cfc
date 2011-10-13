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
 * The ValidationErrorList class defines a well-formed collection of 
 * ValidationExceptions so that groups of validation functions can be 
 * called in a non-blocking fashion.
 * <P>
 * To use the ValidationErrorList to execute groups of validation 
 * attempts, your controller code would look something like:
 * 
 * <PRE>
 * ValidationErrorList() errorList = new ValidationErrorList();.
 * String name  = getValidInput("Name", form.getName(), "SomeESAPIRegExName1", 255, false, errorList);
 * String address = getValidInput("Address", form.getAddress(), "SomeESAPIRegExName2", 255, false, errorList);
 * Integer weight = getValidInteger("Weight", form.getWeight(), 1, 1000000000, false, errorList);
 * Integer sortOrder = getValidInteger("Sort Order", form.getSortOrder(), -100000, +100000, false, errorList);
 * request.setAttribute( "ERROR_LIST", errorList );
 * </PRE>
 * 
 * The at your view layer you would be able to retrieve all
 * of your error messages via a helper function like:
 * 
 * <PRE>
 * public static ValidationErrorList getErrors() {          
 *     HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
 *     ValidationErrorList errors = new ValidationErrorList();
 *     if (request.getAttribute(Constants.ERROR_LIST) != null) {
 *        errors = (ValidationErrorList)request.getAttribute("ERROR_LIST");
 *     }
 *        return errors;
 * }
 * </PRE>
 * 
 * You can list all errors like:
 * 
 * <PRE>
 * <%
 *      for (Object vo : errorList.errors()) {
 *         ValidationException ve = (ValidationException)vo;
 * %>
 * <%= ESAPI.encoder().encodeForHTML(ve.getMessage()) %><br/>
 * <%
 *     }
 * %>
 * </PRE>
 * 
 * And even check if a specific UI component is in error via calls like:
 * 
 * <PRE>
 * ValidationException e = errorList.getError("Name");
 * </PRE>
 * 
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @since August 15, 2008
 */
component ValidationErrorList extends="cfesapi.org.owasp.esapi.lang.Object" {

	// imports
	ArrayList = createObject("java", "java.util.ArrayList");
	RuntimeException = createObject("java", "java.lang.RuntimeException");

	/**
	 * Error list of ValidationException's
	 */
	instance.errorList = {};

	/**
	 * Adds a new error to list with a unique named context.
	 * No action taken if either element is null. 
	 * Existing contexts will be overwritten.
	 * 
	 * @param context Unique named context for this {@code ValidationErrorList}.
	 * @param vex    A {@code ValidationException}.
	 */
	
	public void function addError(required String context, 
	                              required cfesapi.org.owasp.esapi.errors.ValidationException vex) {
		if(!isNull(getError(arguments.context))) {
			throw(object=RuntimeException.init("Context (" & arguments.context & ") already exists, must be unique"));
		}
		instance.errorList.put(arguments.context, arguments.vex);
	}
	
	/**
	 * Returns list of ValidationException, or empty list of no errors exist.
	 * 
	 * @return List
	 */
	
	public Array function errors() {
		return ArrayList.init(instance.errorList.values());
	}
	
	/**
	 * Retrieves ValidationException for given context if one exists.
	 * 
	 * @param context unique name for each error
	 * @return ValidationException or null for given context
	 */
	
	public function getError(required String context) {
		if(structKeyExists(instance.errorList, arguments.context)) {
			return instance.errorList.get(arguments.context);
		}
	}
	
	/**
	 * Returns true if no error are present.
	 * 
	 * @return boolean
	 */
	
	public boolean function isEmpty() {
		return instance.errorList.isEmpty();
	}
	
	/**
	 * Returns the numbers of errors present.
	 * 
	 * @return boolean
	 */
	
	public numeric function size() {
		return instance.errorList.size();
	}
	
}
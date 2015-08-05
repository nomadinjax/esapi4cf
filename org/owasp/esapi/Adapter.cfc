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
interface {

	public function getUserByAccountId(required accountId);
	public function getUserByAccountName(required string accountName);
	public array function getUserNames();
	public void function saveUser(required org.owasp.esapi.User user);
	public void function removeUser(required org.owasp.esapi.User user);
	public void function savePasswordHashes(required org.owasp.esapi.User user, required array hashes);
	public array function getAllHashedPasswords(required org.owasp.esapi.User user);
	public array function getOldPasswordHashes(required org.owasp.esapi.User user);

}
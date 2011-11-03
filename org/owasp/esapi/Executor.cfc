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
 * The Executor interface is used to run an OS command with reduced security risk.
 * 
 * <p>Implementations should do as much as possible to minimize the risk of
 * injection into either the command or parameters. In addition, implementations
 * should timeout after a specified time period in order to help prevent denial
 * of service attacks.</p> 
 * 
 * <p>The class should perform logging and error handling as
 * well. Finally, implementation should handle errors and generate an
 * ExecutorException with all the necessary information.</p>
 *
 * <p>The reference implementation does all of the above.</p>
 */
interface {

	/**
	 * Executes a system command after checking that the executable exists and
	 * escaping all the parameters to ensure that injection is impossible.
	 * Implementations must change to the specified working
	 * directory before invoking the command.
	 *
	 * @param executable
	 *            the command to execute
	 * @param params
	 *            the parameters of the command being executed
	 * @param workdir
	 *            the working directory
	 * @param codec
	 *            the codec to use to encode for the particular OS in use
	 * @param logParams
	 *            use false if any parameters contains sensitive or confidential information
	 *
	 * @return the output of the command being run
	 *
	 * @throws ExecutorException
	 *             the service exception
	 */
	
	public function executeSystemCommand(required executable, required Array params, workdir, codec, boolean logParams, boolean redirectErrorStream);
	
}
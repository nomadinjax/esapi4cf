/**
	 * Loads encrypted properties file based on the location passed in args then prompts the
	 * user to input key-value pairs.  When the user enters a null or blank key, the values
	 * are stored to the properties file.
	 *
	 * @param args
	 *            the location of the properties file to load and write to
	 *
	 * @throws Exception
	 *             Any exception thrown
	 */
	public static void main(String[] args) throws Exception {
		File f = new File(args[0]);
		ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY, true, "Loading encrypted properties from " + f.getAbsolutePath() );
		if ( !f.exists() ) throw new IOException( "Properties file not found: " + f.getAbsolutePath() );
		ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY, true, "Encrypted properties found in " + f.getAbsolutePath() );
		DefaultEncryptedProperties ep = new DefaultEncryptedProperties();

		FileInputStream in = null;
		FileOutputStream out = null;
		try {
    		in = new FileInputStream(f);
            out = new FileOutputStream(f);

            ep.load(in);
    		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
    		String key = null;
    		do {
    			System.out.print("Enter key: ");
    			key = br.readLine();
    			System.out.print("Enter value: ");
    			String value = br.readLine();
    			if (key != null && key.length() > 0 && value != null && value.length() > 0) {
    				ep.setProperty(key, value);
    			}
    		} while (key != null && key.length() > 0);
    		ep.store(out, "Encrypted Properties File");
		} finally {
    		try { in.close(); } catch( Exception e ) {}
    		try { out.close(); } catch( Exception e ) {}
		}

		Iterator i = ep.keySet().iterator();
		while (i.hasNext()) {
			String k = (String) i.next();
			String value = ep.getProperty(k);
			System.out.println("   " + k + "=" + value);
		}
	}
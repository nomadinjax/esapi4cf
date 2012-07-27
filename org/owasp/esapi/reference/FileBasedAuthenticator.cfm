<!---
 * Fail safe main program to add or update an account in an emergency.
 * <P>
 * Warning: this method does not perform the level of validation and checks
 * generally required in ESAPI, and can therefore be used to create a username and password that do not comply
 * with the username and password strength requirements.
 * <P>
 * Example: Use this to add the alice account with the admin role to the users file:
 * <PRE>
 *
 * java -Dorg.owasp.esapi.resources="/path/resources" -classpath esapi.jar org.owasp.esapi.Authenticator alice password admin
 *
 * </PRE>
 *
 * @param args
 * 		the arguments (username, password, role)
 * @throws Exception
 * 		the exception
 --->

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: Authenticator accountname password role");
            return;
        }
        FileBasedAuthenticator auth = new FileBasedAuthenticator();
        String accountName = args[0].toLowerCase();
        String password = args[1];
        String role = args[2];
        DefaultUser user = (DefaultUser) auth.getUser(args[0]);
        if (user == null) {
            user = new DefaultUser(accountName);
    		String newHash = auth.hashPassword(password, accountName);
    		auth.setHashedPassword(user, newHash);
            user.addRole(role);
            user.enable();
            user.unlock();
            auth.userMap.put(new Long(user.getAccountId()), user);
            System.out.println("New user created: " + accountName);
            auth.saveUsers();
            System.out.println("User account " + user.getAccountName() + " updated");
        } else {
        	System.err.println("User account " + user.getAccountName() + " already exists!");
        }
    }
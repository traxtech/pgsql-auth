/**
 * The person or persons who have associated work with this document (the
 * "Dedicator" or "Certifier") hereby either (a) certifies that, to the best of
 * his knowledge, the work of authorship identified is in the public domain of
 * the country from which the work is published, or (b) hereby dedicates
 * whatever copyright the dedicators holds in the work of authorship identified
 * below (the "Work") to the public domain. A certifier, moreover, dedicates any
 * copyright interest he may have in the associated work, and for these
 * purposes, is described as a "dedicator" below.
 *
 * A certifier has taken reasonable steps to verify the copyright status of this
 * work. Certifier recognizes that his good faith efforts may not shield him
 * from liability if in fact the work certified is not in the public domain.
 *
 * Dedicator makes this dedication for the benefit of the public at large and to
 * the detriment of the Dedicator's heirs and successors. Dedicator intends this
 * dedication to be an overt act of relinquishment in perpetuity of all present
 * and future rights under copyright law, whether vested or contingent, in the
 * Work. Dedicator understands that such relinquishment of all rights includes
 * the relinquishment of all rights to enforce (by lawsuit or otherwise) those
 * copyrights in the Work.
 *
 * Dedicator recognizes that, once placed in the public domain, the Work may be
 * freely reproduced, distributed, transmitted, used, modified, built upon, or
 * otherwise exploited by anyone for any purpose, commercial or non-commercial,
 * and in any way, including by methods that have not yet been invented or
 * conceived.
 */
package hudson.plugins.pgsql;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

/**
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses a PostgreSQL
 * database as the source of authentication information.
 * 
 * @author Alex Ackerman
 */
public class PgSQLSecurityRealm extends AbstractPasswordBasedSecurityRealm
{

    @DataBoundConstructor
    public PgSQLSecurityRealm(String myServer, String myUsername, String myPassword,
            String myPort, String myDatabase, String myDataTable, String myUserField,
            String myPassField, String myCondition, String encryption)
    {
        this.myServer = Util.fixEmptyAndTrim(myServer);
        this.myUsername = Util.fixEmptyAndTrim(myUsername);
        this.myPassword = Util.fixEmptyAndTrim(myPassword);
        this.myPort = Util.fixEmptyAndTrim(myPort);
        if ((myPort == null) || (myPort.equals("")))
            myPort = "5432";
        this.myPort = myPort;
        this.myDatabase = Util.fixEmptyAndTrim(myDatabase);
        this.myCondition = Util.fixEmptyAndTrim(myCondition);
        this.myDataTable = Util.fixEmptyAndTrim(myDataTable);
        this.myUserField = Util.fixEmptyAndTrim(myUserField);
        this.myPassField = Util.fixEmptyAndTrim(myPassField);
        this.encryption = encryption;
    }

    public static final class DescriptorImpl extends Descriptor<SecurityRealm>
    {
        @Override
        public String getHelpFile() {
            return "/plugin/pgsql-auth/help/overview.html";
        }
        
        @Override
        public String getDisplayName() {
            return Messages.DisplayName();
        }
    }

    public static String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    @Extension
    public static DescriptorImpl install()
    {
        return new DescriptorImpl();
    }

    /**
     * Authenticates the specified user using the password against the stored
     * database configuration.
     *
     * @param username      The username to lookup
     * @param password      The password to use for authentication
     * @return              A UserDetails object containing information about
     *                      the user.
     * @throws AuthenticationException  Thrown when the username/password do
     *                                  not match stored values.
     */
    @Override
    protected UserDetails authenticate(String username, String password)
            throws AuthenticationException
    {
        UserDetails userDetails = null;

        String connectionString;

        connectionString = "jdbc:postgresql://" + myServer + "/" +
                myDatabase;
        LOGGER.fine("PostgreSQLSecurity: Connection String - " + connectionString);
        Connection conn = null;
        try
        {
            // Connect to the database
            Class.forName("org.postgresql.Driver").newInstance();
            conn = DriverManager.getConnection(connectionString,
                    myUsername, myPassword);
            LOGGER.info("PostgreSQLSecurity: Connection established.");

            // Prepare the statement and query the user table
            // TODO: Review userQuery to see if there's a better way to do this
            String userQuery = "SELECT * FROM " + myDataTable + " WHERE " +
                    myUserField + " = ?";
            LOGGER.info("PostgreSQLSecurity: prepare statement '" + userQuery + "'");
            PreparedStatement statement = conn.prepareStatement(userQuery);
            LOGGER.info("PostgreSQLSecurity: XXX.1");
            LOGGER.info("PostgreSQLSecurity: Query Info - ");
            LOGGER.info("- Table: " + myDataTable);
            LOGGER.info("- User Field: " + myUserField);
            LOGGER.info("- Username: " + myUsername);
            //statement.setString(2, myUserField);
            statement.setString(1, username);
            LOGGER.info("PostgreSQLSecurity: XXX.2");
            ResultSet results = statement.executeQuery();
            LOGGER.info("PostgreSQLSecurity: XXX.3");
            LOGGER.fine("PostgreSQLSecurity: Query executed.");

            if (results.next())
            {
                String storedPassword = results.getString(myPassField);

                boolean matched = false;

                if (encryption.equals("PLAIN")) {
                    matched = password.equals(storedPassword);
                } else if(encryption.equals("JASYPTBASIC")) {
                    matched = new StrongPasswordEncryptor().checkPassword(password, storedPassword);
                } else if(encryption.equals("JASYPTSTRONG")) {
                    matched = new StrongPasswordEncryptor().checkPassword(password, storedPassword);
                } else {
                    MessageDigest md = MessageDigest.getInstance(encryption);
                    md.update(password.getBytes());
                    String digested = getHexString(md.digest());
                    matched = digested.toLowerCase().equalsIgnoreCase(storedPassword.toLowerCase());
                }
                /*
                Cipher cipher;
                if (encryption.equals(Cipher.CRYPT))
                {
                    String salt = storedPassword.substring(0, 2);
                    cipher = new Cipher(encryption, salt);
                }
                else
                {
                    cipher = new Cipher(encryption);
                }
                String encryptedPassword = cipher.encode(password.trim()).toLowerCase();
                 *
                 */
                LOGGER.info("Encryption: " + encryption);
                LOGGER.info("Given Password: " + password);
                LOGGER.info("Stored Password: " + storedPassword);
                //if (!storedPassword.equals(encryptedPassword))
                if(!matched)
                {
                    LOGGER.warning("PostgreSQLSecurity: Invalid Username or Password - no match");
                    throw new PgSQLAuthenticationException("Invalid Username or Password");
                }
                else
                {
                    LOGGER.info("Passwords match");
                    // Password is valid.  Build UserDetail
                    Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
                    groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
                    userDetails = new PgSQLUserDetail(username, storedPassword,
                            true, true, true, true,
                            groups.toArray(new GrantedAuthority[groups.size()]));
                }
            }
            else
            {
                LOGGER.warning("PostgreSQLSecurity: Invalid Username or Password - no user");
                throw new PgSQLAuthenticationException("Invalid Username or Password");
            }

        }
        catch (Exception e)
        {
            e.printStackTrace();
            LOGGER.warning("PostgreSQLSecurity Realm Error: " + e.getLocalizedMessage());
        }
        finally
        {
            if (conn != null)
            {
                try
                {
                    conn.close();
                    LOGGER.info("PostgreSQLSecurity: Connection closed.");
                }
                catch (Exception ex)
                {
                    /** Ignore any errors **/
                }
            }
        }

        return userDetails;
    }

    /**
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException
    {
        UserDetails user = null;
        String connectionString;

        connectionString = "jdbc:pgsql://" + myServer + "/" +
                myDatabase;
        LOGGER.info("PostgreSQLSecurity: Connection String - " + connectionString);
        Connection conn = null;
        try
        {
            // Connect to the database
            Class.forName("com.pgsql.jdbc.Driver").newInstance();
            conn = DriverManager.getConnection(connectionString,
                    myUsername, myPassword);
            LOGGER.info("PostgreSQLSecurity: Connection established.");

            // Prepare the statement and query the user table
            // TODO: Review userQuery to see if there's a better way to do this
            String userQuery = "SELECT * FROM " + myDataTable + " WHERE " +
                    myUserField + " = ?";
            PreparedStatement statement = conn.prepareStatement(userQuery);
            //statement.setString(1, myDataTable);
            //statement.setString(2, myUserField);
            statement.setString(1, username);
            ResultSet results = statement.executeQuery();
            LOGGER.fine("PostgreSQLSecurity: Query executed.");

            // Grab the first result (should be only user returned)
            if (results.first())
            {
                // Build the user detail
                Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
                groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
                user = new PgSQLUserDetail(username, results.getString(myPassField),
                            true, true, true, true, 
                            groups.toArray(new GrantedAuthority[groups.size()]));
            }
            else
            {
                LOGGER.warning("PostgreSQLSecurity: Invalid Username or Password");
                throw new UsernameNotFoundException("PostgreSQL: User not found");
            }

        }
        catch (Exception e)
        {
            LOGGER.warning("PostgreSQLSecurity Realm Error: " + e.getLocalizedMessage());
        }
        finally
        {
            if (conn != null)
            {
                try
                {
                    conn.close();
                    LOGGER.info("PostgreSQLSecurity: Connection closed.");
                }
                catch (Exception ex)
                {
                    /** Ignore any errors **/
                }
            }
        }
        return user;
    }

    /**
     *
     * @param groupname
     * @return
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public GroupDetails loadGroupByGroupname(String groupname)
            throws UsernameNotFoundException, DataAccessException
    {
        LOGGER.warning("ERROR: Group lookup is not supported.");
        throw new UsernameNotFoundException("PostgreSQLSecurityRealm: Non-supported function");
    }

    class Authenticator extends AbstractUserDetailsAuthenticationProvider
    {

        @Override
        protected void additionalAuthenticationChecks(UserDetails userDetails,
                UsernamePasswordAuthenticationToken authentication)
                throws AuthenticationException {
            // Assumed to be done in the retrieveUser method
        }

        @Override
        protected UserDetails retrieveUser(String username,
                UsernamePasswordAuthenticationToken authentication)
                throws AuthenticationException {
            return PgSQLSecurityRealm.this.authenticate(username,
                    authentication.getCredentials().toString());
        }

    }

    public String getMyServer()
    {
        return myServer;
    }

    public String getMyUsername()
    {
        return myUsername;
    }

    public String getMyPassword()
    {
        return myPassword;
    }

    public String getMyDatabase()
    {
        return myDatabase;
    }

    public String getMyDataTable()
    {
        return myDataTable;
    }

    public String getMyUserField()
    {
        return myUserField;
    }

    public String getMyPassField()
    {
        return myPassField;
    }

    public String getMyPort()
    {
        return myPort;
    }
    
    public String getMyCondition()
    {
        return myCondition;
    }

    public String getEncryption()
    {
        return encryption;
    }

    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER =
            Logger.getLogger(PgSQLSecurityRealm.class.getName());

    /**
     * The PostgreSQL server to use.
     */
    private String myServer;
    /**
     * The PostgreSQL username to use to connect to the database server.
     */
    private String myUsername;
    /**
     * The PostgreSQL password to use to connect to the database server.
     */
    private String myPassword;
    /**
     * The database containing the user's authentication information.
     */
    private String myDatabase;
    /**
     * The table containing a user's authentication information.
     */
    private String myDataTable;
    /**
     * Username field in the database.
     */
    private String myUserField;
    /**
     * Password field in the database.
     */
    private String myPassField;
    /**
     * Port used by the PostgreSQL server.  If not specified, defaults to 3306.
     */
    private String myPort;
    /**
     * Condition string which may prevent user from being enabled.  This is a
     * field used by Bugzilla.
     */
    private String myCondition;

    /**
     * Encryption type used for the password
     */
    private String encryption;

}

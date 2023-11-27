import dev.gemfire.ToolBox;
import org.apache.geode.security.ResourcePermission;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;



import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.SortControl;
import java.util.Hashtable;
import org.junit.jupiter.api.Assertions;

import static dev.gemfire.ToolBox.setupShiro;

public class TestLdapSecurityManager {
    @Test
    public void testJNDI() throws Exception {


        LdapContext ctx = (LdapContext) new InitialDirContext(createCommonJNDIEnv()).lookup("ou=Users,dc=example,dc=org");

        NamingEnumeration<SearchResult> res = ctx.search("", "(objectClass=person)", new SearchControls());

        Assertions.assertTrue(res.hasMore());
        SearchResult searchResult = res.next();

        Assertions.assertEquals("uid=jmartin",searchResult.getName());
    }

    @Test
    public void testJNDILoadFromProperties() throws Exception {
        Hashtable env = createCommonJNDIEnv();

        LdapContext ctx = (LdapContext) new InitialDirContext(env).lookup("ou=groups,dc=example,dc=org");

        NamingEnumeration<SearchResult> res = ctx.search("", "(cn=GemFireDeveloper)", new SearchControls());
        Assertions.assertTrue(res.hasMore());
        SearchResult searchResult = res.next();
        Assertions.assertEquals("cn=GemFireDeveloper",searchResult.getName());
    }
    private Hashtable createCommonJNDIEnv() {
        Hashtable env = new Hashtable();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389/");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=org");
        env.put(Context.SECURITY_CREDENTIALS, "admin");
        return env;
    }

    @Test
    public void shiroAdminAndDevUserTest() {

        SecurityManager securityManager = ToolBox.setupShiro("classpath:gf-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("jmartin", "password1234");
        Subject currentUser = SecurityUtils.getSubject();

        currentUser.login(token);
        Assertions.assertTrue(currentUser.hasRole("GemFireDeveloper"));
        Assertions.assertTrue(currentUser.isPermitted("CLUSTER:MANAGE:GATEWAY"));
    }

    @Test
    public void checkForClusterManage() {
        SecurityManager securityManager = ToolBox.setupShiro("classpath:gf-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("clusterManage", "password1234");
        Subject currentUser = SecurityUtils.getSubject();
        currentUser.login(token);
        ResourcePermission resourcePermission = new ResourcePermission("CLUSTER", "MANAGE");

        Assertions.assertTrue(currentUser.hasRole("GemFireClusterManage"));
        Assertions.assertTrue(currentUser.isPermitted(resourcePermission));
    }

}

package com.example.bwce;

import java.net.URI;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/** Stateless Java Invoke helper; uses the JVM's TLS truststore. */
public final class LdapUserLookup {
    private LdapUserLookup() { }

    /**
     * Returns true on the first matching entry, false on a successful empty search.
     * NamingException means the answer could not be determined.
     * filterTemplate is trusted deployment configuration with a {0} value placeholder.
     * Example AD filter: (&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))
     */
    public static boolean userExists(String ldapsUrl, String bindPrincipal,
            String bindPassword, String baseDn, String filterTemplate,
            String username, int connectTimeoutMs, int readTimeoutMs,
            int searchTimeoutMs) throws NamingException {
        requireText(ldapsUrl, "ldapsUrl");
        URI uri = URI.create(ldapsUrl);
        if (!"ldaps".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getQuery() != null
                || uri.getFragment() != null
                || (uri.getRawPath() != null && !uri.getRawPath().isEmpty()
                    && !"/".equals(uri.getRawPath()))
                || uri.getPort() == 0 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("Use ldaps://hostname:636 without credentials, base DN or query");
        }
        requireText(bindPrincipal, "bindPrincipal");
        // An empty password can cause an unauthenticated bind on some directories.
        if (bindPassword == null || bindPassword.isEmpty()) {
            throw new IllegalArgumentException("bindPassword must not be empty");
        }
        requireText(baseDn, "baseDn");
        requireText(filterTemplate, "filterTemplate");
        if (!filterTemplate.contains("{0}")) {
            throw new IllegalArgumentException("filterTemplate must contain {0}");
        }
        requireText(username, "username");
        if (connectTimeoutMs <= 0 || readTimeoutMs <= 0 || searchTimeoutMs <= 0) {
            throw new IllegalArgumentException("All timeouts must be positive milliseconds");
        }

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapsUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindPrincipal);
        env.put(Context.SECURITY_CREDENTIALS, bindPassword);
        // Do not forward service credentials to referral destinations.
        env.put(Context.REFERRAL, "throw");
        env.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(connectTimeoutMs));
        env.put("com.sun.jndi.ldap.read.timeout", Integer.toString(readTimeoutMs));
        env.put("java.naming.ldap.derefAliases", "never");

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setTimeLimit(searchTimeoutMs);
        controls.setCountLimit(1);
        controls.setReturningAttributes(new String[0]);
        controls.setReturningObjFlag(false);

        DirContext context = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            context = new InitialDirContext(env);
            // JNDI escapes special filter characters in the username argument.
            results = context.search(baseDn, filterTemplate, new Object[] {username}, controls);
            return results.hasMore();
        } finally {
            // Cleanup must not replace the original bind/search failure.
            if (results != null) {
                try { results.close(); } catch (NamingException ignored) { }
            }
            if (context != null) {
                try { context.close(); } catch (NamingException ignored) { }
            }
            env.clear();
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}

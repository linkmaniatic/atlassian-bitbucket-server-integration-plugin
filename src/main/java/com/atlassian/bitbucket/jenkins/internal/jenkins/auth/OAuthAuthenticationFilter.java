package com.atlassian.bitbucket.jenkins.internal.jenkins.auth;

import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.OAuthRequestUtils;
import com.atlassian.bitbucket.jenkins.internal.provider.JenkinsProvider;
import hudson.Extension;
import hudson.init.Initializer;
import hudson.init.Terminator;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.util.PluginServletFilter;
import jenkins.security.SecurityListener;
import net.oauth.OAuthProblemException;
import net.oauth.server.OAuthServlet;
import org.acegisecurity.Authentication;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import javax.inject.Inject;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

import static com.atlassian.bitbucket.jenkins.internal.jenkins.auth.OAuthRequestHandler.Result.Status.*;
import static hudson.init.InitMilestone.PLUGINS_PREPARED;
import static java.lang.String.format;
import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import static org.apache.commons.lang3.StringUtils.startsWithIgnoreCase;

/**
 * Authentication filter responsible for ensuring requests with an OAuth access token are
 * authenticated.
 */
@Extension
public class OAuthAuthenticationFilter implements Filter {

    private static final Logger log = Logger.getLogger(OAuthAuthenticationFilter.class.getName());

    @Inject
    private JenkinsProvider jenkinsProvider;
    @Inject
    private OAuthRequestHandler requestHandler;

    @Override
    public void destroy() {
        // Nothing to do before destroy
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String authorization = req.getHeader("Authorization");

        if (startsWithIgnoreCase(authorization, "OAuth ") && OAuthRequestUtils.isOAuthAccessAttempt(req)) {
            OAuthRequestHandler.Result result = requestHandler.handle(req, resp);
            if (result.getStatus() == ERROR || result.getStatus() == FAILED) {
                log.severe("Failed to authenticate OAuth authentication request. Reason - " + result.getMessage());
                return;
            } else if (result.getStatus() == SUCCESS) {
                String user = result.getPrincipalName();
                authenticateUser(req, resp, chain, user);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private void authenticateUser(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                  String user) throws ServletException, IOException {
        User u = User.getById(user, false);
        if (u != null) {
            Authentication auth;
            try {
                UserDetails userDetails = u.getUserDetailsForImpersonation();
                auth = u.impersonate(userDetails);
                SecurityListener.fireAuthenticated(userDetails);
            } catch (UsernameNotFoundException ex) {
                log.log(WARNING,
                        "Access token matched for user " + u.getFullName() +
                        " but the impersonation failed", ex);
                throw new ServletException(ex);
            }

            if (auth != null) {
                try (ACLContext ignored = ACL.as(auth)) {
                    chain.doFilter(request, response);
                }
            }
        } else {
            sendError(response, format("User %s not found in system", user));
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // No initialisation needed
    }

    @Initializer(after = PLUGINS_PREPARED)
    public void onStart() {
        try {
            PluginServletFilter.addFilter(this);
        } catch (ServletException e) {
            log.log(SEVERE, "Failed to add filter in filter chain", e);
        }
    }

    @Terminator
    public void onStop() {
        try {
            PluginServletFilter.removeFilter(this);
        } catch (ServletException e) {
            log.log(WARNING, "Failed to remove filter from filter chain", e);
        }
    }

    private void sendError(HttpServletResponse response, String problem) throws IOException, ServletException {
        OAuthServlet.handleException(response, new OAuthProblemException(""), jenkinsProvider.get().getRootUrl());
    }
}

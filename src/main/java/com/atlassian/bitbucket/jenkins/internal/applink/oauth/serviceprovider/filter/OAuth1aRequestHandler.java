package com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.filter;

import com.atlassian.bitbucket.jenkins.internal.applink.oauth.OAuthConverter;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.consumer.Consumer;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.consumer.ConsumerStore;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.exception.InvalidTokenException;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token.ServiceProviderToken;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token.ServiceProviderTokenStore;
import com.atlassian.bitbucket.jenkins.internal.jenkins.auth.OAuthRequestHandler;
import com.atlassian.bitbucket.jenkins.internal.provider.JenkinsProvider;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.OAuthValidator;
import net.oauth.server.OAuthServlet;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.atlassian.bitbucket.jenkins.internal.applink.oauth.util.OAuthProblemUtils.logOAuthProblem;
import static com.atlassian.bitbucket.jenkins.internal.applink.oauth.util.OAuthProblemUtils.logOAuthRequest;
import static java.lang.String.format;
import static java.util.logging.Level.*;
import static javax.servlet.RequestDispatcher.FORWARD_REQUEST_URI;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static net.oauth.OAuth.Problems.*;

public class OAuth1aRequestHandler implements OAuthRequestHandler {

    private static final Logger log = Logger.getLogger(OAuth1aRequestHandler.class.getName());

    private final String baseUrl;
    private final ConsumerStore consumerStore;
    private final ServiceProviderTokenStore tokenStore;
    private final OAuthValidator validator;
    private final Clock clock;

    @Inject
    public OAuth1aRequestHandler(JenkinsProvider jenkinsProvider,
                                 ConsumerStore consumerStore,
                                 ServiceProviderTokenStore tokenStore,
                                 OAuthValidator validator,
                                 Clock clock) {
        this(jenkinsProvider.get().getRootUrl(), consumerStore, tokenStore, validator, clock);
    }

    OAuth1aRequestHandler(String baseUrl,
                          ConsumerStore consumerStore,
                          ServiceProviderTokenStore tokenStore,
                          OAuthValidator validator,
                          Clock clock) {
        this.baseUrl = baseUrl;
        this.consumerStore = consumerStore;
        this.tokenStore = tokenStore;
        this.validator = validator;
        this.clock = clock;
    }

    public Result handle(HttpServletRequest request, HttpServletResponse response) {
        OAuthMessage message = OAuthServlet.getMessage(request, getLogicalUri(request));

        // 3LO needs to start with oauth_token
        String tokenStr;
        try {
            tokenStr = message.getToken();
        } catch (IOException e) {
            // this would be really strange if it happened, but take precautions just in case
            log.log(Level.SEVERE, "3-Legged-OAuth Failed to read token from request", e);
            sendError(response, SC_INTERNAL_SERVER_ERROR, message);
            logOAuthRequest(request, "OAuth authentication FAILED - Unreadable token", log);
            return new Result.Error("Unreadable token");
        }

        Optional<ServiceProviderToken> mayBeToken;
        ServiceProviderToken token;
        try {
            try {
                // the oauth_token must exist and it has to be valid
                mayBeToken = tokenStore.get(tokenStr);
            } catch (InvalidTokenException e) {
                log.log(FINE, format("3-Legged-OAuth Consumer provided token [%s] rejected by ServiceProviderTokenStore", tokenStr), e);
                throw new OAuthProblemException(TOKEN_REJECTED);
            }

            // various validations on the token
            if (!mayBeToken.isPresent()) {
                if (log.isLoggable(FINE)) {
                    log.log(FINE, format("3-Legged-OAuth token rejected. Service Provider Token, for Consumer provided token [%s], is null", tokenStr));
                }

                throw new OAuthProblemException(TOKEN_REJECTED);
            }
            token = mayBeToken.get();

            if (!token.isAccessToken()) {
                if (log.isLoggable(FINE)) {
                    log.log(FINE, format("3-Legged-OAuth token rejected. Service Provider Token, for Consumer provided token [%s], is NOT an access token.", tokenStr));
                }

                throw new OAuthProblemException(TOKEN_REJECTED);
            }

            if (token.getUser() == null) {
                if (log.isLoggable(FINE)) {
                    log.log(FINE, format("3-Legged-OAuth token rejected. Service Provider Token, for Consumer provided token [%s], does not have a corresponding user.", tokenStr));
                }

                throw new OAuthProblemException("No user associated with the token");
            }

            if (!token.getConsumer().getKey().equals(message.getConsumerKey())) {
                if (log.isLoggable(FINE)) {
                    log.log(FINE, format("3-Legged-OAuth token rejected. Service Provider Token, for Consumer provided token [%s], consumer key [%s] does not match request consumer key [%s]", tokenStr, token.getConsumer().getKey(), message.getConsumerKey()));
                }

                throw new OAuthProblemException(TOKEN_REJECTED);
            }

            if (token.hasExpired(clock)) {
                if (log.isLoggable(FINE)) {
                    log.log(FINE, format("3-Legged-OAuth token rejected. Token has expired. Token creation time [%d] time to live [%d] clock (contains logging delay) [%d]", token.getCreationTime(), token.getTimeToLive(), clock.millis()));
                }

                throw new OAuthProblemException(TOKEN_EXPIRED);
            }
            validate3LOMessage(message, token);
            validateConsumer(message);
        } catch (OAuthProblemException ope) {
            return handleOAuthProblemException(response, message, tokenStr, ope);
        } catch (Exception e) {
            return handleException(response, message, e);
        }

        return new Result.Success(token.getUser().getName());
    }

    private void printMessageToDebug(OAuthMessage message) throws IOException {
        if (!log.isLoggable(FINE)) {
            return;
        }

        StringBuilder sb = new StringBuilder("Validating incoming OAuth request:\n");
        sb.append("\turl: ").append(message.URL).append("\n");
        sb.append("\tmethod: ").append(message.method).append("\n");
        for (Map.Entry<String, String> entry : message.getParameters()) {
            sb.append("\t").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
        }
        log.log(FINE, sb.toString());
    }

    private void sendError(HttpServletResponse response, int status, OAuthMessage message) {
        response.setStatus(status);
        try {
            response.addHeader("WWW-Authenticate", message.getAuthorizationHeader(baseUrl));
        } catch (IOException e) {
            log.log(SEVERE, "Failure reporting OAuth error to client", e);
        }
    }

    private Consumer validateConsumer(OAuthMessage message) throws IOException, OAuthException {
        // This consumer must exist at the time the token is used.
        final String consumerKey = message.getConsumerKey();
        final Consumer consumer = consumerStore.get(consumerKey);

        if (consumer == null) {
            log.log(INFO, "Unknown consumer key:'{}' supplied in OAuth request" + consumerKey);
            throw new OAuthProblemException(CONSUMER_KEY_UNKNOWN);
        }

        return consumer;
    }

    private Result handleOAuthProblemException(HttpServletResponse response, OAuthMessage message, String tokenStr,
                                               OAuthProblemException ope) {
        logOAuthProblem(message, ope, log);
        try {
            OAuthServlet.handleException(response, ope, baseUrl);
        } catch (Exception e) {
            // there was an IOE or ServletException, nothing more we can really do
            log.log(SEVERE, "Failure reporting OAuth error to client", e);
        }

        if (ope.getProblem().equals(CONSUMER_KEY_UNKNOWN)) {
            return new Result.Failure(ope.getMessage());
        }

        if (tokenStr != null) {
            return new Result.Failure(ope.getMessage() + ", Input token - " + tokenStr);
        } else {
            return new Result.Failure(ope.getMessage());
        }
    }

    private Result handleException(HttpServletResponse response, OAuthMessage message, Exception e) {
        // this isn't likely to happen, it would result from some unknown error with the request that the OAuth.net
        // library couldn't handle appropriately
        log.log(SEVERE, "Failed to process OAuth message", e);
        sendError(response, SC_INTERNAL_SERVER_ERROR, message);
        return new Result.Error("System Problem");
    }

    private String getLogicalUri(HttpServletRequest request) {
        String uriPathBeforeForwarding = (String) request.getAttribute(FORWARD_REQUEST_URI);
        if (uriPathBeforeForwarding == null) {
            return null;
        }
        URI newUri = URI.create(request.getRequestURL().toString());
        try {
            return new URI(newUri.getScheme(), newUri.getAuthority(),
                    uriPathBeforeForwarding,
                    newUri.getQuery(),
                    newUri.getFragment()).toString();
        } catch (URISyntaxException e) {
            log.log(WARNING, "forwarded request had invalid original URI path: " + uriPathBeforeForwarding);
            return null;
        }
    }

    private void validate3LOMessage(OAuthMessage message, ServiceProviderToken token)
            throws OAuthException, IOException, URISyntaxException {
        printMessageToDebug(message);

        validator.validateMessage(message, OAuthConverter.createOAuthAccessor(token));
    }
}

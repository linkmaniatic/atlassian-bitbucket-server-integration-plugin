package com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token;

import com.atlassian.bitbucket.jenkins.internal.applink.oauth.Randomizer;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.consumer.Consumer;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.exception.InvalidTokenException;
import net.oauth.OAuthMessage;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.net.URI;
import java.util.logging.Logger;

import static com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token.ServiceProviderToken.newAccessToken;
import static com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token.ServiceProviderToken.newRequestToken;
import static java.lang.System.currentTimeMillis;
import static java.util.Objects.requireNonNull;
import static java.util.UUID.randomUUID;
import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Implementation of {@link TokenFactory} that uses randomly generated values for tokens and delegates storage of
 * generated tokens to {@link ServiceProviderTokenStore}.
 * <br>
 * The random token generation is based on the
 * <a href="https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth/src/main/java/org/springframework/security/oauth/provider/token/RandomValueProviderTokenServices.java">Spring OAuth Provider Library</a>
 */
@Singleton
public class RandomValueTokenFactory implements TokenFactory {

    private static final int ACCESS_TOKEN_SESSION_LENGTH_BYTES = 80;
    private static final int TOKEN_SECRET_LENGTH_BYTES = 80;

    private static final Logger log = Logger.getLogger(RandomValueTokenFactory.class.getName());

    private final Randomizer randomizer;

    @Inject
    public RandomValueTokenFactory(Randomizer randomizer) {
        this.randomizer = randomizer;
    }

    @Override
    public ServiceProviderToken generateAccessToken(ServiceProviderToken requestToken) {
        requireNonNull(requestToken, "requestToken");

        if (requestToken.isAccessToken()) {
            log.warning("Token is not a request token: " + requestToken);
            throw new InvalidTokenException("Token is not a request token");
        }

        if (requestToken.getUser() == null || isBlank(requestToken.getVerifier())) {
            log.warning("Request token is not authorized: " + requestToken);
            throw new InvalidTokenException("Request token is not authorized");
        }

        log.fine(String.format("Request token '%s' was used to generate an access token", requestToken));

        return newAccessToken(randomUUID().toString())
                .callback(requestToken.getCallback())
                .consumer(requestToken.getConsumer())
                .creationTime(currentTimeMillis())
                .tokenSecret(randomizer.randomUrlSafeString(TOKEN_SECRET_LENGTH_BYTES))
                .authorizedBy(requestToken.getUser())
                .verifier(requestToken.getVerifier())
                .session(newSession(requestToken))
                .build();
    }

    @Override
    public ServiceProviderToken generateRequestToken(Consumer consumer, @Nullable URI callback, OAuthMessage message) {
        requireNonNull(consumer, "consumer");
        return newRequestToken(randomUUID().toString())
                .callback(callback)
                .consumer(consumer)
                .creationTime(currentTimeMillis())
                .tokenSecret(randomizer.randomUrlSafeString(TOKEN_SECRET_LENGTH_BYTES))
                .build();
    }

    private ServiceProviderToken.Session newSession(ServiceProviderToken token) {
        ServiceProviderToken.Session.Builder builder =
                ServiceProviderToken.Session.newSession(randomizer.randomUrlSafeString(ACCESS_TOKEN_SESSION_LENGTH_BYTES));
        if (token.getSession() != null) {
            builder.creationTime(token.getSession().getCreationTime());
        }
        return builder.build();
    }
}

package com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token;

import com.atlassian.bitbucket.jenkins.internal.applink.oauth.Randomizer;
import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.exception.InvalidTokenException;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URI;
import java.security.Principal;
import java.util.Objects;

import static com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token.ServiceProviderToken.newAccessToken;
import static com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token.ServiceProviderToken.newRequestToken;
import static com.atlassian.bitbucket.jenkins.internal.applink.oauth.util.TestData.Consumers.RSA_CONSUMER;
import static java.lang.System.currentTimeMillis;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RandomValueTokenFactoryTest {

    @Mock
    private Randomizer randomizer;

    @InjectMocks
    private RandomValueTokenFactory tokenFactory;

    private static TokenMatcher accessToken(URI callback, String consumerKey, String secret) {
        return new TokenMatcher(true, callback, consumerKey, secret);
    }

    private static TokenMatcher requestToken(URI callback, String consumerKey, String secret) {
        return new TokenMatcher(false, callback, consumerKey, secret);
    }

    @Test
    public void testGenerateAccessToken() {
        URI callback = URI.create("http://some-callback-url/endpoint");
        String reqTokenValue = "req-token1";
        Principal user = mock(Principal.class);
        ServiceProviderToken requestToken = newRequestToken(reqTokenValue)
                .callback(callback)
                .consumer(RSA_CONSUMER)
                .creationTime(currentTimeMillis())
                .tokenSecret("the-secret-token")
                .authorizedBy(user)
                .verifier("a1b2c3")
                .build();
        String tokenSecret = "test-token-secret";
        when(randomizer.randomUrlSafeString(anyInt())).thenReturn(tokenSecret);

        ServiceProviderToken accessToken = tokenFactory.generateAccessToken(requestToken);

        assertThat(accessToken, accessToken(callback, RSA_CONSUMER.getKey(), tokenSecret));
    }

    @Test(expected = InvalidTokenException.class)
    public void testGenerateAccessTokenInputIsAccessToken() {
        URI callback = URI.create("http://some-callback-url/endpoint");
        String tokenValue = "req-token1";
        Principal user = mock(Principal.class);
        ServiceProviderToken token = newAccessToken(tokenValue)
                .callback(callback)
                .consumer(RSA_CONSUMER)
                .creationTime(currentTimeMillis())
                .tokenSecret("the-secret-token")
                .authorizedBy(user)
                .verifier("a1b2c3")
                .build();

        tokenFactory.generateAccessToken(token);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateAccessTokenNullInput() {
        tokenFactory.generateAccessToken(null);
    }

    @Test(expected = InvalidTokenException.class)
    public void testGenerateAccessTokenRequestTokenNotFound() {
        URI callback = URI.create("http://some-callback-url/endpoint");
        String tokenValue = "req-token1";
        ServiceProviderToken token =
                newRequestToken(tokenValue)
                        .callback(callback)
                        .consumer(RSA_CONSUMER)
                        .creationTime(currentTimeMillis())
                        .tokenSecret("the-secret-token")
                        .build();

        tokenFactory.generateAccessToken(token);
    }

    @Test
    public void testGenerateRequestToken() {
        URI callback = URI.create("http://some-callback-url/endpoint");
        String tokenSecret = "test-token-secret";
        when(randomizer.randomUrlSafeString(anyInt())).thenReturn(tokenSecret);

        ServiceProviderToken requestToken = tokenFactory.generateRequestToken(RSA_CONSUMER, callback, null);

        assertThat(requestToken, requestToken(callback, RSA_CONSUMER.getKey(), tokenSecret));
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateRequestTokenConsumerIsNull() {
        tokenFactory.generateRequestToken(null, URI.create("http://some-callback-url/endpoint"), null);
    }

    private static final class TokenMatcher extends TypeSafeDiagnosingMatcher<ServiceProviderToken> {

        private final boolean accessToken;
        private final String secret;
        private final URI callback;
        private final String consumerKey;

        private TokenMatcher(boolean accessToken, URI callback, String consumerKey, String secret) {
            this.callback = callback;
            this.consumerKey = consumerKey;
            this.accessToken = accessToken;
            this.secret = secret;
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("token [type=")
                    .appendValue(accessToken ? "ACCESS" : "REQUEST")
                    .appendText(", callback=")
                    .appendValue(callback)
                    .appendText(", consumer.key=")
                    .appendValue(consumerKey)
                    .appendText(", secret=")
                    .appendValue(secret)
                    .appendText(", token value is not blank]");
        }

        @Override
        protected boolean matchesSafely(ServiceProviderToken token, Description description) {
            if (token == null) {
                description.appendText("is null");
                return false;
            }
            boolean matches = (accessToken ? token.isAccessToken() : token.isRequestToken()) &&
                    Objects.equals(callback, token.getCallback()) &&
                    Objects.equals(secret, token.getTokenSecret()) &&
                    token.getConsumer() != null &&
                    Objects.equals(consumerKey, token.getConsumer().getKey()) &&
                    isNotBlank(token.getToken());
            if (!matches) {
                description.appendText("token [type=")
                        .appendValue(token.isAccessToken() ? "ACCESS" : "REQUEST")
                        .appendText(", callbackUrl=")
                        .appendValue(callback)
                        .appendText(", secret=")
                        .appendValue(token.getTokenSecret())
                        .appendText(", token=")
                        .appendValue(token.getToken());
                if (token.getConsumer() == null) {
                    description.appendText(", consumer is null");
                } else {
                    description.appendText(", consumer.key=")
                            .appendValue(token.getConsumer().getKey());
                }
                description.appendText("]");
            }
            return matches;
        }
    }
}

package com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token;

import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.exception.InvalidTokenException;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import static org.mockito.Mockito.mock;

@RunWith(MockitoJUnitRunner.class)
public class RandomValueTokenFactoryTest {

    private RandomValueTokenFactory tokenFactory;

    private static TokenMatcher accessToken(URI callback, String consumerKey) {
        return new TokenMatcher(callback, consumerKey, true);
    }

    private static TokenMatcher requestToken(URI callback, String consumerKey) {
        return new TokenMatcher(callback, consumerKey, false);
    }

    @Before
    public void setup() {
        tokenFactory = new RandomValueTokenFactory();
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

        ServiceProviderToken accessToken = tokenFactory.generateAccessToken(requestToken);

        assertThat(accessToken, accessToken(callback, RSA_CONSUMER.getKey()));
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

        ServiceProviderToken requestToken = tokenFactory.generateRequestToken(RSA_CONSUMER, callback, null);

        assertThat(requestToken, requestToken(callback, RSA_CONSUMER.getKey()));
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateRequestTokenConsumerIsNull() {
        tokenFactory.generateRequestToken(null, URI.create("http://some-callback-url/endpoint"), null);
    }

    private static final class TokenMatcher extends TypeSafeDiagnosingMatcher<ServiceProviderToken> {

        private final URI callback;
        private final String consumerKey;
        private final boolean accessToken;

        private TokenMatcher(URI callback, String consumerKey, boolean accessToken) {
            this.callback = callback;
            this.consumerKey = consumerKey;
            this.accessToken = accessToken;
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("token [type=")
                    .appendValue(accessToken ? "ACCESS" : "REQUEST")
                    .appendText(", callback=")
                    .appendValue(callback)
                    .appendText(", consumer.key=")
                    .appendValue(consumerKey)
                    .appendText(", secret is not blank")
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
                    isNotBlank(token.getTokenSecret()) &&
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

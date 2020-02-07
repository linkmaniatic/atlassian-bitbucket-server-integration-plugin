package com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.token;

import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.consumer.Consumer;
import com.google.inject.ImplementedBy;
import net.oauth.OAuthMessage;

import javax.annotation.Nullable;
import java.net.URI;

/**
 * Provides methods for generating request and access tokens.
 */
@ImplementedBy(RandomValueTokenFactory.class)
public interface TokenFactory {

    /**
     * Generate an unauthorized request token.
     *
     * @param consumer Consumer information for generating the request token
     * @param callback parsed and validated OAuth callback {@code URI}
     * @param message  OAuth message that can be used to grab any additional parameters to use when creating the request token
     */
    ServiceProviderToken generateRequestToken(Consumer consumer, @Nullable URI callback, OAuthMessage message);

    /**
     * Returns a newly generated access token for the authorized request token.
     *
     * @param token an authorized request token
     * @throws IllegalArgumentException thrown if the token is not an authorized request token
     */
    ServiceProviderToken generateAccessToken(ServiceProviderToken token);
}

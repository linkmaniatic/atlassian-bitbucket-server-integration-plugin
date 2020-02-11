package com.atlassian.bitbucket.jenkins.internal.jenkins.auth;

import com.atlassian.bitbucket.jenkins.internal.applink.oauth.serviceprovider.filter.OAuth1aRequestHandler;
import com.google.inject.ImplementedBy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@ImplementedBy(OAuth1aRequestHandler.class)
public interface OAuthRequestHandler {

    /**
     * Handles a request
     *
     * @param request  The request
     * @param response The response
     * @return The result of the Oauth handling
     */
    Result handle(HttpServletRequest request, HttpServletResponse response);

    /**
     * Encapsulates the results of an OAuth token validation attempt.  Includes the result status, any problem that
     * occurred, and possibly the authenticated users name.
     */
    class Result {

        private final Result.Status status;
        private final String message;
        private final String principleName;

        Result(final Result.Status status, final String message) {
            this(status, message, null);
        }

        Result(final Result.Status status, final String message, final String principleName) {
            if (status == null) {
                throw new NullPointerException("status");
            }
            if (message == null) {
                throw new NullPointerException("message");
            }
            this.status = status;
            this.message = message;
            this.principleName = principleName;
        }

        public Result.Status getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }

        public String getPrincipalName() {
            return principleName;
        }

        public enum Status {
            SUCCESS("success"),
            FAILED("failed"),
            ERROR("error");

            private final String name;

            Status(final String name) {
                this.name = name;
            }

            @Override
            public String toString() {
                return name;
            }
        }

        public static final class Error extends Result {

            public Error(final String message) {
                super(Status.ERROR, message);
            }
        }

        public static final class Failure extends Result {

            public Failure(final String message) {
                super(Status.FAILED, message);
            }
        }

        public static final class Success extends Result {

            /**
             * Construct a success result for a particular principal.
             *
             * @param principalName the successfully-authenticated principal
             */
            public Success(final String principalName) {
                super(Status.SUCCESS, "Successful authentication", principalName);
            }
        }
    }
}

package com.atlassian.bitbucket.jenkins.internal.trigger;

import com.atlassian.bitbucket.jenkins.internal.config.BitbucketPluginConfiguration;
import com.atlassian.bitbucket.jenkins.internal.model.BitbucketMirrorServer;
import com.atlassian.bitbucket.jenkins.internal.model.BitbucketNamedLink;
import com.atlassian.bitbucket.jenkins.internal.model.BitbucketRefChangeType;
import com.atlassian.bitbucket.jenkins.internal.model.BitbucketRepository;
import com.atlassian.bitbucket.jenkins.internal.scm.BitbucketSCM;
import com.atlassian.bitbucket.jenkins.internal.scm.BitbucketSCMRepository;
import hudson.plugins.git.GitSCM;
import hudson.scm.SCM;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.triggers.Trigger;
import hudson.triggers.TriggerDescriptor;
import jenkins.model.Jenkins;
import jenkins.model.ParameterizedJobMixIn;
import jenkins.triggers.SCMTriggerItem;
import org.eclipse.jgit.transport.RemoteConfig;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static org.apache.commons.lang3.StringUtils.isBlank;

@Singleton
public class BitbucketWebhookConsumer {

    private static final Logger LOGGER = Logger.getLogger(BitbucketWebhookConsumer.class.getName());

    @Inject
    private BitbucketPluginConfiguration bitbucketPluginConfiguration;

    void process(RefsChangedWebhookEvent event) {
        BitbucketRepository repository = event.getRepository();
        LOGGER.fine(format("Received refs changed event from repo: %s/%s  ", repository.getProject().getKey(), repository.getSlug()));
        if (!isEligibleRefs(event)) {
            return;
        }
        RefChangedDetails refChangedDetails = new RefChangedDetails(event);
        triggerJob(event, refChangedDetails);
    }

    void process(MirrorSynchronizedWebhookEvent event) {
        BitbucketRepository repository = event.getRepository();
        LOGGER.fine(format("Received Mirror Synchronized changed event from repo: %s/%s  ", repository.getProject().getKey(), repository.getSlug()));
        if (!isEligibleRefs(event)) {
            return;
        }
        RefChangedDetails refChangedDetails = new RefChangedDetails(event);
        triggerJob(event, refChangedDetails);
    }

    private boolean isEligibleRefs(RefsChangedWebhookEvent event) {
        if (eligibleRefs(event).isEmpty()) {
            LOGGER.fine("Skipping processing of refs changed event because no refs have been added or updated");
            return false;
        }
        return true;
    }

    private void triggerJob(RefsChangedWebhookEvent event,
                            RefChangedDetails refChangedDetails) {
        try (ACLContext ctx = ACL.as(ACL.SYSTEM)) {
            BitbucketWebhookTriggerRequest.Builder requestBuilder = BitbucketWebhookTriggerRequest.builder();
            event.getActor().ifPresent(requestBuilder::actor);

            Jenkins.get().getAllItems(ParameterizedJobMixIn.ParameterizedJob.class)
                    .stream()
                    .map(BitbucketWebhookConsumer::toTriggerDetails)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .filter(triggerDetails -> hasMatchingRepository(refChangedDetails, triggerDetails.getJob()))
                    .peek(triggerDetails -> LOGGER.fine("Triggering " + triggerDetails.getJob().getFullDisplayName()))
                    .forEach(triggerDetails -> triggerDetails.getTrigger().trigger(requestBuilder.build()));
        }
    }

    private static Set<String> eligibleRefs(RefsChangedWebhookEvent event) {
        return event.getChanges()
                .stream()
                .filter(refChange -> refChange.getType() != BitbucketRefChangeType.DELETE)
                .map(refChange -> refChange.getRef().getId())
                .collect(Collectors.toSet());
    }

    private static Collection<? extends SCM> getScms(ParameterizedJobMixIn.ParameterizedJob<?, ?> job) {
        SCMTriggerItem triggerItem = SCMTriggerItem.SCMTriggerItems.asSCMTriggerItem(job);
        if (triggerItem != null) {
            return triggerItem.getSCMs();
        }
        return Collections.emptySet();
    }

    private static boolean hasMatchingRepository(RefChangedDetails refChangedDetails,
                                                 GitSCM scm) {
        return scm.getRepositories().stream()
                .anyMatch(scmRepo -> matchingRepo(refChangedDetails.getCloneLinks(), scmRepo));
    }

    private static boolean matchingRepo(Set<String> cloneLinks, RemoteConfig repo) {
        return repo.getURIs().stream().anyMatch(uri -> {
            String uriStr = uri.toString();
            return cloneLinks.stream()
                    .anyMatch(link -> link.equalsIgnoreCase(uriStr));
        });
    }

    private static boolean matchingRepo(BitbucketRepository repository, BitbucketSCMRepository scmRepo) {
        return scmRepo.getProjectKey().equalsIgnoreCase(repository.getProject().getKey()) &&
               scmRepo.getRepositorySlug().equalsIgnoreCase(repository.getSlug());
    }

    private static Optional<TriggerDetails> toTriggerDetails(ParameterizedJobMixIn.ParameterizedJob<?, ?> job) {
        BitbucketWebhookTriggerImpl trigger = triggerFrom(job);
        if (trigger != null) {
            return of(new TriggerDetails(job, trigger));
        }
        return empty();
    }

    @Nullable
    private static BitbucketWebhookTriggerImpl triggerFrom(ParameterizedJobMixIn.ParameterizedJob<?, ?> job) {
        Map<TriggerDescriptor, Trigger<?>> triggers = job.getTriggers();
        for (Trigger<?> candidate : triggers.values()) {
            if (candidate instanceof BitbucketWebhookTriggerImpl) {
                return (BitbucketWebhookTriggerImpl) candidate;
            }
        }
        return null;
    }

    private boolean hasMatchingRepository(RefChangedDetails refChangedDetails,
                                          ParameterizedJobMixIn.ParameterizedJob<?, ?> job) {
        Collection<? extends SCM> scms = getScms(job);
        for (SCM scm : scms) {
            if (scm instanceof GitSCM) {
                return hasMatchingRepository(refChangedDetails, (GitSCM) scm);
            } else if (scm instanceof BitbucketSCM) {
                return hasMatchingRepository(refChangedDetails, (BitbucketSCM) scm);
            }
        }
        return false;
    }

    private boolean hasMatchingRepository(RefChangedDetails refChangedDetails,
                                          BitbucketSCM scm) {
        if (refChangedDetails.isMirrorSyncEvent() && !refChangedDetails.getMirrorName().equals(scm.getMirrorName())) {
            return false;
        }
        return bitbucketPluginConfiguration.getServerById(scm.getServerId())
                .map(serverConfig -> {
                    String selfLink = refChangedDetails.getRepository().getSelfLink();
                    if (isBlank(selfLink) || selfLink.startsWith(serverConfig.getBaseUrl())) {
                        return scm.getRepositories().stream()
                                .anyMatch(scmRepo -> matchingRepo(refChangedDetails.getRepository(), scmRepo));
                    }
                    LOGGER.info(format("Base URL of incoming repository selflink - [%s] and bitbucket server configured URL - [%s] seems to be be different",
                            isBlank(selfLink) ? "unknown" : selfLink,
                            serverConfig.getBaseUrl()));
                    return false;
                }).orElse(false);
    }

    private static final class RefChangedDetails {

        private final Set<String> cloneLinks;
        private final BitbucketRepository repository;
        private final String mirrorName;
        private final boolean isMirrorSyncEvent;

        private RefChangedDetails(RefsChangedWebhookEvent event) {
            this.cloneLinks = cloneLinks(event);
            this.repository = event.getRepository();
            this.mirrorName = "";
            this.isMirrorSyncEvent = false;
        }

        private RefChangedDetails(MirrorSynchronizedWebhookEvent event) {
            this.cloneLinks = cloneLinks(event);
            this.repository = event.getRepository();
            this.mirrorName = event.getMirrorServer().map(BitbucketMirrorServer::getName).orElse("");
            this.isMirrorSyncEvent = true;
        }

        public Set<String> getCloneLinks() {
            return cloneLinks;
        }

        public String getMirrorName() {
            return mirrorName;
        }

        public BitbucketRepository getRepository() {
            return repository;
        }

        public boolean isMirrorSyncEvent() {
            return isMirrorSyncEvent;
        }

        private static Set<String> cloneLinks(RefsChangedWebhookEvent event) {
            return event.getRepository()
                    .getCloneUrls()
                    .stream()
                    .map(BitbucketNamedLink::getHref)
                    .collect(Collectors.toSet());
        }
    }

    private static final class TriggerDetails {

        private final ParameterizedJobMixIn.ParameterizedJob<?, ?> job;
        private final BitbucketWebhookTrigger trigger;

        private TriggerDetails(ParameterizedJobMixIn.ParameterizedJob<?, ?> job, BitbucketWebhookTrigger trigger) {
            this.job = job;
            this.trigger = trigger;
        }

        public ParameterizedJobMixIn.ParameterizedJob<?, ?> getJob() {
            return job;
        }

        public BitbucketWebhookTrigger getTrigger() {
            return trigger;
        }
    }
}
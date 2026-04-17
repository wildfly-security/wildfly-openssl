# Release Process

Before releasing WildFly OpenSSL it is assumed that this project has already been updated to the required version
of WildFly OpenSSL Natives.

Presently Java 25 should be used to perform the release.

To release WildFly OpenSSL first checkout the project and ensure you are on the latest commit for the branch you are releasing with no local changes.

Prior to releasing you should ensure you have your own GPG signing key set up, published to a key server and listed on [wildfly.org](https://www.wildfly.org/contributors/pgp/).

## Prepare the release

Execute:

    mvn release:prepare

Enter the version being released:

    What is the release version for "WildFly Elytron - WildFly OpenSSL"? (wildfly-openssl) 3.0.4.CR1: 3.0.4.Alpha1

The tag will default to the version:

    What is the SCM release tag or label for "WildFly Elytron - WildFly OpenSSL"? (wildfly-openssl) 3.0.4.Alpha1:

Set the next version:

    What is the new development version for "WildFly Elytron - WildFly OpenSSL"? (wildfly-openssl) 3.0.5.Alpha1-SNAPSHOT: 3.0.4.CR1-SNAPSHOT

The release commit can be checked with:

    git show ${TAG}

If everything is Ok perform the release which will deploy to Nexus.

## Perform the release

Execute:

    mvn release:perform

This will deploy the release to the `wildfly-staging` repository.

Run the validation job for the `wildfly-staging` repository and check that there are no errors.

e.g.

> Processed 5 components.
> - no errors were found.
> - the deployment was a dry run (no actual publishing).

If others are also deploying at the same time this count could be higher, the important check is that the scan was at least 10 minutes after it was deployed, 1 or more components were scanned and no errors specific to WildFly OpenSSL are reported.

Nexus only scans components once if there are no issues so if you check these results after multiple scans the component count may be back to 0.

## Complete the release

If no issues are reported complete the release.

Move the component to the `wildfly-security` repository:

    git checkout ${TAG}
    mvn nxrm3:staging-move
    git checkout ${BRANCH}

Push the branch and tag to GitHub:

    git push upstream ${BRANCH}
    git push upstream ${TAG}

## Rollback the Release

If the release failed, revert the release.

Delete the component from Nexus:

    git checkout ${TAG}
    mvn nxrm3:staging-delete
    git checkout ${BRANCH}

Reset your local Git checkout:

    git reset --hard upstream/${BRANCH}
    git tag --delete ${TAG}


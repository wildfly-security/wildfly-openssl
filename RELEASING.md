Release Process
===============

The release process for this project is not a simple one. Because it requires Windows, Linux and Mac artifacts it is necessary
to perform it over 3 different machines.

The basic process is:

Perform the tag and push it to github as normal.

The first step is to deploy the parent, and the current platforms native library:

    mvn clean install deploy -Dparent-release

Release these artifacts in nexus, then on the other two platforms check out the tag and run:

    mvn clean install deploy

This will deploy the shared library for these platforms.

To deploy the actual shaded jar run:

    mvn clean install deploy -Drelease

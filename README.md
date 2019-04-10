# awssig
This is a Burp extension for signing AWS requests with SigV4. The Signature Version 4 is a process that one needs to use to add authentication information to AWS HTTP requests. More information can be found here: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

For more information directly contact the main author at: *brian.bauer@anvilventures.com*.

## Features
- Credentials can be automatically imported from a file.
- Profiles are automatically selected based on the key id in the request
- Option to force a certain profile to be used


## Build Instructions
This assumes maven is installed properly as well as a Java Development Kit.

```
$ cd src
$ mvn package
[INFO] Scanning for projects...
[INFO]
[INFO] ---------------------------< groupId:awsig >----------------------------
[INFO] Building awsig 1.0-SNAPSHOT
[INFO] --------------------------------[ jar ]---------------------------------
[...]
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  1.590 s
[INFO] Finished at: 2019-04-10T08:31:35+02:00
[INFO] ------------------------------------------------------------------------
$ ls target
archive-tmp
awsig-1.0-SNAPSHOT-jar-with-dependencies.jar
awsig-1.0-SNAPSHOT.jar
classes
generated-sources
maven-archiver
maven-status
```

That should result in a newly created `target` directory containing class files
as well as two JARs. One containing all the dependencies named
`awsig-<version>-jar-with-dependencies.jar` and the other just named
`awsig-<version>.jar`. Those should then be able to be loaded by Burp.

Loading the project up in IntelliJ IDEA should also make it easy to build the
source.

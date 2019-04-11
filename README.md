# awsig
This is a Burp extension for signing AWS requests with SigV4. Signature Version 4 is a process to add authentication information to AWS HTTP requests. More information can be found here: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

## Features
- Credentials can be imported from a file.
- Profiles are automatically selected based on the key id in the request.
- Resend requests with different credentials.
- Supports signatures in query string parameters or headers.


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


## Usage
Hit the "Import Profiles" button to automatically import credentials. See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-where.

At a minimum, a profile should contain a keyId and a secretKey. Outgoing requests will be signed with the key associated with the keyId in the original request. If the keyId is not recognized, the message will be sent unmodifed. Alternatively, a "Default Profile" can be set which will be used to sign all outgoing requests regardless of the original keyId.

region and service should almost always be left blank with the checkbox under "auto" selected. This will ensure the region and service in the original request are used which is what is wanted in most cases.

Profiles will be saved in the Burp settings store, including AWS keys, if "Persist Profiles" is checked.

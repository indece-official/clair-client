# clair-client
Command line client for [quay/clair v4](https://github.com/quay/clair/)

## Installation
* Download [latest Release](https://github.com/indece-official/clair-client/releases/latest)
* Move binary to `/usr/local/bin/clair-client`

## Usage
```
$> clair-client -docker-registry https://docker.mysite.com -image myorg/myimage:latest -docker-username myusername -docker-password mypassword -clair-url https://clair.mysite.com  -whitelist ./config/whitelist
```

```
Usage of clair-client:
  -clair-index-timeout int
        Index timeout for clair (default 120s)
  -clair-password string
        Clair password
  -clair-url string
        Clair URL
  -clair-username string
        Clair username
  -docker-password string
        Docker registry password
  -docker-registry string
        Docker Registry
  -docker-username string
        Docker registry username
  -image string
        Url of docker image
  -max-severity string
        Maximum severity regarded as ok (default "Medium")
  -quiet
        Be quiet
  -v    
        Print the version info and exit
  -whitelist string
        Name of whitelist file for CVEs
```

Output:
```
Logging into docker registry https://docker.mysite.com ...
Loading docker manifest for image myorg/myimage:latest from registry ...
Indexing docker manifest in clair ...
Waiting for indexing of docker manifest in clair to finish ...
Generating vulnerability report ...
Processing vulnerability report ...

+--------------------------------+----------+--------------------------------+---------+-----------+-------------+
| VULNERABILITY                  | SEVERITY | COMPONENT                      | VERSION | FIXEDIN   | WHITELISTED |
+--------------------------------+----------+--------------------------------+---------+-----------+-------------+
| CVE-2021-22890                 | Unknown  | Alpine Linux v3.12 > curl      |         | 7.76.0-r0 | false       |
| pyup.io-39252                  | Unknown  | cryptography                   | <3.3    |           | false       |
| pyup.io-39606 (CVE-2020-36242) | Unknown  | cryptography                   | <3.3.2  |           | false       |
| pyup.io-38932 (CVE-2020-25659) | Unknown  | cryptography                   | <=3.2   |           | false       |
| CVE-2021-30139                 | Unknown  | Alpine Linux v3.12 > apk-tools |         | 2.10.6-r0 | true        |
| CVE-2020-8284                  | Unknown  | Alpine Linux v3.12 > curl      |         | 7.74.0-r0 | false       |
| CVE-2021-22876                 | Unknown  | Alpine Linux v3.12 > curl      |         | 7.76.0-r0 | false       |
+--------------------------------+----------+--------------------------------+---------+-----------+-------------+

Found 0 vulnerabilities with severity 'Medium' or more (0 whitelisted)

```

Exits with code 1 when non-whitelisted vulnerabilities with an severity above `max-severity` were found.

### Whitelist file
Example:

```
# This is a comment
CVE-2021-30139
CVE-2020-8284
```

### Tested Clair-Servers
| Version | Status |
| --- | --- |
| v4.0.5 | OK |
| v4.1.0 | OK |

## Development
### Snapshot build

```
$> make --always-make
```

### Release build

```
$> BUILD_VERSION=1.0.0 make --always-make
```
# Getting started with ImprovedSecAudit.py
This code assumes that credentials and configurations are stored in a location recognized by boto3.
This includes *~/.aws/credentials* among other locations.
It currently does not allow passing credentials in as arguments, but that is on the to-do list.


## Use within client-specific environments
Clients I work with often have their own devices that intercept TLS calls to Amazon APIs. Handling this requires setting the AWS_CA_BUNDLE environment variable with the private CA used by the security appliance.
Alternately, you can set the *verify=False* parameter when you establish the session. This approach is recommended for testing purposes only.
Some documentation implies that you can also use *verify=/path/to/cert-bundle.crt* in the connection that creates the session but I've not yet tried this.


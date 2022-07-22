Mandatory Elements:
- targetDomain
- certificateArn

Commands:
    pulumi config set aws:profile <profile_name>
    pulumi config set targetDomain <FQDN>
    pulumi config set certificateArn <ACM_ARN>

    Optional:
    pulumi config set aws:skipCredentialsValidation true

import pulumi_aws as aws
from pulumi import export, Config, Output

# Read the configuration for this stack.
stack_config = Config()
target_domain = stack_config.require('targetDomain')
certificate_arn = stack_config.require('certificateArn')
current = aws.s3.get_canonical_user_id()

aws_cloudfront_origin_access_identity = aws.cloudfront.OriginAccessIdentity("static-frontend", comment="OAI for Static Frontend")

# Create an S3 bucket configured as a website bucket.
content_bucket = aws.s3.Bucket('contentBucket',
    bucket=target_domain,
    acl='private',
    website=aws.s3.BucketWebsiteArgs(
        index_document='index.html',
        error_document='404.html'
    ),
    versioning=aws.s3.BucketVersioningArgs(
        enabled=True,
    ),
    lifecycle_rules=[aws.s3.BucketLifecycleRuleArgs(
        enabled=True,
        noncurrent_version_expiration=aws.s3.BucketLifecycleRuleNoncurrentVersionExpirationArgs(days=90),
        expiration=aws.s3.BucketLifecycleRuleExpirationArgs(expired_object_delete_marker=True)
    )]
)

s3_policy = aws.iam.get_policy_document(statements=[aws.iam.GetPolicyDocumentStatementArgs(
    effect="Allow",
    actions=["s3:GetObject"],
    resources=[content_bucket.arn.apply(lambda arn: f"{arn}/*")],
    principals=[aws.iam.GetPolicyDocumentStatementPrincipalArgs(
        type="AWS",
        identifiers=[aws_cloudfront_origin_access_identity.iam_arn],
    )],
)])

bucket_policy = aws.s3.BucketPolicy("contentBucketPolicy",
    bucket=content_bucket.id,
    policy=s3_policy.json
)

bucket_public_access_block = aws.s3.BucketPublicAccessBlock("ContentBucketPublicAccessBlock",
    bucket=content_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True
)

bucket_ownership_controls = aws.s3.BucketOwnershipControls("ContentBucketOwnershipControls",
    bucket=content_bucket.id,
    rule=aws.s3.BucketOwnershipControlsRuleArgs(object_ownership="BucketOwnerEnforced")
)

# Create a logs bucket for the CloudFront logs
logs_bucket = aws.s3.Bucket('requestLogs', 
    bucket=f'{target_domain}-logs',
    acl='private',
    lifecycle_rules=[
        aws.s3.BucketLifecycleRuleArgs(
            enabled=True,
            expiration=aws.s3.BucketLifecycleRuleExpirationArgs(days=30)
        )
    ]
)

log_bucket_public_access_block = aws.s3.BucketPublicAccessBlock("LogBucketPublicAccessBlock",
    bucket=logs_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True
)

log_bucket_ownership_controls = aws.s3.BucketOwnershipControls("LogBucketOwnershipControls",
    bucket=logs_bucket.id,
    rule=aws.s3.BucketOwnershipControlsRuleArgs(object_ownership="BucketOwnerPreferred")
)

example_bucket_acl_v2 = aws.s3.BucketAclV2("CloudFrontAccessLogsBucketAcl",
    bucket=logs_bucket.id,
    access_control_policy=aws.s3.BucketAclV2AccessControlPolicyArgs(
        grants=[
            aws.s3.BucketAclV2AccessControlPolicyGrantArgs(
                grantee=aws.s3.BucketAclV2AccessControlPolicyGrantGranteeArgs(
                    id='c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0',
                    type="CanonicalUser",
                ),
                permission="FULL_CONTROL",
            ),
            aws.s3.BucketAclV2AccessControlPolicyGrantArgs(
                grantee=aws.s3.BucketAclV2AccessControlPolicyGrantGranteeArgs(
                    id=current.id,
                    type="CanonicalUser",
                ),
                permission="FULL_CONTROL",
            ),
        ],
        owner=aws.s3.BucketAclV2AccessControlPolicyOwnerArgs(
            id=current.id,
        ),
    ))


# Create the CloudFront distribution
TEN_MINUTES = 60 * 10

cdn = aws.cloudfront.Distribution('cdn',
    enabled=True,
    aliases=[
        target_domain
    ],
    origins=[aws.cloudfront.DistributionOriginArgs(
        origin_id=content_bucket.arn,
        domain_name=content_bucket.bucket_domain_name,
        s3_origin_config=aws.cloudfront.DistributionOriginS3OriginConfigArgs(
            origin_access_identity=aws_cloudfront_origin_access_identity.cloudfront_access_identity_path
        )
    )],
    default_root_object='index.html',
    default_cache_behavior=aws.cloudfront.DistributionDefaultCacheBehaviorArgs(
        target_origin_id=content_bucket.arn,
        viewer_protocol_policy='redirect-to-https',
        allowed_methods=['GET', 'HEAD', 'OPTIONS'],
        cached_methods=['GET', 'HEAD', 'OPTIONS'],
        forwarded_values=aws.cloudfront.DistributionDefaultCacheBehaviorForwardedValuesArgs(
            cookies=aws.cloudfront.DistributionDefaultCacheBehaviorForwardedValuesCookiesArgs(forward='none'),
            query_string=False,
        ),
        min_ttl=0,
        default_ttl=TEN_MINUTES,
        max_ttl=TEN_MINUTES,
    ),
    # PriceClass_100 is the lowest cost tier (US/EU only).
    price_class='PriceClass_100',
    custom_error_responses=[aws.cloudfront.DistributionCustomErrorResponseArgs(
        error_code=404,
        response_code=404,
        response_page_path='/404.html'
    )],
    # Use the certificate we generated for this distribution.
    viewer_certificate=aws.cloudfront.DistributionViewerCertificateArgs(
        acm_certificate_arn=certificate_arn,
        ssl_support_method='sni-only',
        minimum_protocol_version='TLSv1.2_2021'
    ),
    restrictions=aws.cloudfront.DistributionRestrictionsArgs(
        geo_restriction=aws.cloudfront.DistributionRestrictionsGeoRestrictionArgs(
            restriction_type='none'
        )
    ),
    # Put access logs in the log bucket we created earlier.
    logging_config=aws.cloudfront.DistributionLoggingConfigArgs(
        bucket=logs_bucket.bucket_domain_name,
        include_cookies=False,
        prefix=f'${target_domain}/',
    ),
    # CloudFront typically takes 15 minutes to fully deploy a new distribution.
    # Skip waiting for that to complete.
    wait_for_deployment=False
)

# Export the bucket URL, bucket website endpoint, and the CloudFront distribution information.
export('content_bucket_url', Output.concat('s3://', content_bucket.bucket))
export('content_bucket_website_endpoint', content_bucket.website_endpoint)
export('cloudfront_domain', cdn.domain_name)
export('target_domain_endpoint', f'https://{target_domain}/')

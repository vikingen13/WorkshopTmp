/* This query lists Publicly Accessible RDS Instances. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'rds.amazonaws.com'  
    AND eventname = 'CreateDBInstance'  
    AND ELEMENT_AT(requestParameters, 'publiclyAccessible' 
    ) = 'true'SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'rds.amazonaws.com'  
    AND eventname = 'CreateDBInstance'  
    AND ELEMENT_AT(requestParameters, 'publiclyAccessible' 
    ) = 'true'
/* 

This query displays the CloudTrail Lake logs in a flatten table format. This query expands the following objecs: 
userIdentity, userIdentity.sessionContext, userIdentity.sessionContext.attributes, userIdentity.sessionContext.sessionIssuer, 
userIdentity.sessionContext.webidfederationData, and tlsDetails. This query is useful when you are trying to display all 
attributes in an object. This query is helpful to see what colums you can use to pull from the objects available in CloudTrail.

Limitation: This query does not expand Array object. If you are going to attempt to flatten an array, use element_at function.
Eg: element_at(requestParameters, 'ipPermissions')

Note: Add filter Criteria in the where clause to filter the result set. Without a filter criteria, this query will scann all 
the data and will result to very slow query.

*/

SELECT
    eventVersion,
    userIdentity.principalID,
    userIdentity.arn,
    userIdentity.accountID,
    userIdentity.accessKeyID,
    userIdentity.username,
    userIdentity.sessionContext.attributes.creationDate,
    userIdentity.sessionContext.attributes.mfaAuthenticated,
    userIdentity.sessionContext.sessionIssuer.type,
    userIdentity.sessionContext.sessionIssuer.principalID,
    userIdentity.sessionContext.sessionIssuer.arn,
    userIdentity.sessionContext.sessionIssuer.accountID,
    userIdentity.sessionContext.sessionIssuer.username,
    userIdentity.sessionContext.webidfederationData.federatedProvider,
    userIdentity.sessionContext.webidfederationData.attributes,
    userIdentity.sessionContext.sourceIdentity,
    userIdentity.sessionContext.ec2RoleDelivery,
    userIdentity.sessionContext.ec2IssuedInVPC,
    userIdentity.invokedBy,
    userIdentity.identityProvider,
    eventTime,
    eventSource,
    eventName,
    awsRegion,
    sourceIpAddress,
    userAgent,
    errorCode,
    errorMessage,
    requestParameters,
    responseElements,
    additionalEventData,
    requestID,
    eventID,
    readOnly,
    resources,
    eventType,
    apiVersion,
    managementEvent,
    recipientAccountID,
    sharedEventID,
    annotation,
    vpcEndPointID,
    serviceEventDetails,
    addendum,
    edgeDeviceDetails,
    insightDetails,
    eventCategory,
    tlsDetails.tlsVersion,
    tlsDetails.cipherSuite,
    tlsDetails.clientProvidedHostHeader,
    sessionCredentialFromConsole,
    eventJson,
    eventJsonChecksum
FROM
    <event_data_store_id>
WHERE eventTime >= '${date_filter}'
    AND eventTime <= '${date_filter}'
    -- Add filter Criteria in the where clause to filter the result set.
    -- Without a filter criteria, this query will scann all the data and will result to very slow query.
/* This query returns all requests by user by account for the specified time period. Ordered by request count. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.principalid, useridentity.accountId, count(* 
    ) as eventCount 
FROM
    $EDS_ID 
WHERE
    userIdentity.principalid IS NOT NULL  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'
GROUP
    BY userIdentity.principalid, useridentity.accountId ORDER BY EventCount DESC
/* This query returns details when a RDS DB was deleted without taking final snapshot.
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    element_at(requestParameters, 'dBClusterIdentifier' 
    ) as DBCluster, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as DeletedTime
FROM
    $EDS_ID 
WHERE
    eventName = 'DeleteDBCluster'  
    and element_at(requestParameters, 'skipFinalSnapshot' 
    ) = 'true'
/* 
This query returns the PutEvaluation result for Config rules.

Essentially providing the same information returned by the overall resource compliance CI type.
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT
    eventTime,awsRegion, recipientAccountId, element_at(additionalEventData, 'configRuleName'  
    ) as configRuleName, json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceType' 
    ) as Compliance, json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceResourceType' 
    ) as ResourceType, json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceResourceId' 
    ) as ResourceName
FROM
    <event_data_store_id>
WHERE
    eventName='PutEvaluations'  
    AND eventTime > '2023-11-16 00:00:00'  
    AND eventTime < '2023-11-17 00:00:00' 
    And json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceType' 
    ) IN ('COMPLIANT','NON_COMPLIANT'
    ) 
/* This query returns Aurora PostgreSQL databases with Availability zone information.
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    element_at(requestParameters, 'dBInstanceIdentifier'
    ) as DBInstance, element_at(requestParameters, 'engine'
    ) as Engine, element_at(requestParameters, 'engineVersion'
    ) as DBEngineVersion,  element_at(requestParameters, 'availabilityZone'
    ) as AvailabilityZone
FROM
    $EDS_ID 
WHERE
    element_at(requestParameters, 'engine'
    ) = 'aurora-postgresql' 
    and eventname = 'CreateDBInstance' 
    and eventTime >='2021-01-01 00:00:00' 
    and eventTime < '2022-01-01 00:00:00'
/*This query can be used for troubleshooting purposes as it lists all the error messages for S3 source.  You can use the query for all resources, just modifying the eventSource.
Replace <EDS ID> with your Event Data Store Id number.*/

select
    eventType, eventName, errorMessage 
from
    <event_data_store_id> 
where
    errorMessage is not null  
    and eventSource='s3.amazonaws.com'example: select
        eventType, eventName, errorMessage  
    from
        <event_data_store_id>  
    where
        errorMessage is not null  
        and eventSource='s3.amazonaws.com'
/* 
This query returns activity based on mutable APIs and the AWS services performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT eventSource, eventName, eventTime, eventID, errorCode
FROM <EDS ID>
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND readOnly = false
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query confirms who (principal Id) has launched an EC2 instance.
Replace <EDS ID> with your Event Data Store Id number and the <i-b188560f> with the EC2 instance that you are looking for.
*/

SELECT userIdentity.principalid, eventName, eventTime, recipientAccountId, awsRegion 
FROM <EDS ID>
WHERE responseElements IS NOT NULL AND
element_at(responseElements, 'instancesSet') like '%'instanceId':'i-b188560f'%' 
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND eventName='RunInstances'

/* This query lists the count of data events by API actions for a specified S3 bucket
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    eventName, COUNT(*
    ) as requestCount
FROM
    $EDS_ID
WHERE
    eventSource = 's3.amazonaws.com' 
    AND eventCategory = 'Data' 
    AND eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND element_at(requestParameters, 'bucketName'
    ) = 'my-bucket-name'
GROUP
    BY eventNameORDER BY requestCount DESC
/* 
This query returns information about API IAM CreateUserAccessKeys performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventID, eventTime, errorCode, errorMessage
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='CreateAccessKey'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query returns API IAM CreateRole called by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventID, eventTime, errorCode, errorMessage
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='CreateRole'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query returns information about API IAM CreateUser performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventID, eventTime, element_at(responseElements, 'user') as userInfo
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='CreateUser'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query helps to confirm in which AWS accounts the IAM Identify Center user has federated using which IAM roles during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT element_at(serviceEventDetails, 'account_id') as AccountID, element_at(serviceEventDetails, 'role_name') as SSORole, eventID, eventTime
FROM <EDS ID>
WHERE eventSource = 'sso.amazonaws.com'
AND eventName = 'Federate'
AND userIdentity.username = 'alice@example.com'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* This query returns summary of regions in use and well as what services are used in these regions.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    awsRegion, eventSource, COUNT(*  
    ) AS apiCount 
FROM
    $EDS_ID 
WHERE
    eventTime > '2022-04-23 00:00:00'  
    AND eventTime < '2022-11-26 00:00:00' 
GROUP
    BY awsRegion, eventSource ORDER BY apiCount DESC
/* 
This query returns AWS API activity performed by an IAM user access key and from which IP address during specific time window ordered by AWS service.
Replace <EDS ID> with your Event Data Store Id number and <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT eventSource,eventName,sourceIPAddress,eventTime,errorCode
FROM <EDS ID>
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
order by eventTime;

/*

This query returns historical changes of security groups. This is useful when you are auditing / investigating
changes made to security groups.

Notice that there are two queries below that are being combined using the 'UNION ALL' clause. 

The first query pulls the AuthorizeSecurityGroupIngress events (for newly created security group rules).
The 2nd query pulls the ModifySecurityGroupRulesRequest (for modification on security group rules).

*/

-- This part of the query returns AuthorizeSecurityGroupIngress events
SELECT
    element_at(requestParameters, 'groupId') AS securityGroup,
    eventName,
    eventTime,
    element_at(requestParameters, 'ipPermissions') AS securityGroupRule,
    userIdentity.arn AS user,
    sourceIPAddress,    
    eventSource
FROM
    <event_data_store_id>
WHERE
    eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-08 00:00:00'
    AND eventName = 'AuthorizeSecurityGroupIngress'     

UNION ALL

-- This part of the query returns ModifySecurityGroupRulesRequest events
SELECT
    json_extract_scalar(element_at(requestParameters, 'ModifySecurityGroupRulesRequest'), '$.GroupId') securityGroup,
    eventName,
    eventTime,
    element_at(requestParameters, 'ModifySecurityGroupRulesRequest') securityGroupRule,
    userIdentity.arn AS user,
    sourceIPAddress,    
    eventSource
FROM
    <event_data_store_id>
WHERE
	eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-09 00:00:00'
	AND eventName = 'ModifySecurityGroupRules'
ORDER BY securityGroup,
    eventTime
/* This query lists raw records for all EC2 management events.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventname IN ('AssociateAddress', 'DisassociateAddress', 'CancelReservedInstancesListing', 'CancelSpotInstanceRequests', 'CreateNetworkAcl', 'DeleteNetworkAcl', 'CreateNetworkAclEntry', '''CreateVpc' , 'DeleteVpcPeeringConnection', 'RevokeSecurityGroupIngress' , 'RevokeSecurityGroupEgress', 'DetachInternetGateway', 'PurchaseReservedInstancesOffering', 'ModifyReservedInstances', 'AcceptVpcPeeringConnection', 'RejectVpcPeeringConnection' , 'CreateVpcPeeringConnection' 
    )
/* This query returns raw records for all 'scan' DunamoDB management events.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'dynamodb.amazonaws.com'  
    AND eventname = 'scan'
/* 

This query returns the historical changes on the public access block policy of s3 buckets. This query is useful when you are 
trying to audit public access block changes or trying to find buckets that are exposed in the internet.

If you are trying to find the current bucket policy that are allowing public access, look at the result set of this query.
Check for the first record of each bucket from the result set. Check each bucket and check if the blockPublicPolicy = false.

*/

SELECT
	element_at(requestParameters, 'bucketName') AS bucketName,
    json_extract_scalar(element_at(requestParameters, 'PublicAccessBlockConfiguration'), '$.RestrictPublicBuckets') AS restrictPublicBuckets,
    json_extract_scalar(element_at(requestParameters, 'PublicAccessBlockConfiguration'), '$.BlockPublicPolicy') AS blockPublicPolicy,
    element_at(requestParameters, 'PublicAccessBlockConfiguration') AS publicAccessBlockConfiguration,
    eventName,
    eventTime,
    requestParameters,
    userIdentity.arn AS user,
    responseElements
FROM
    <event_data_store_id>
WHERE
    eventTime >= '2023-07-07 00:00:00'
    AND eventSource = 's3.amazonaws.com'
    and element_at(requestParameters, 'bucketName') = 'demo-20230707'
    and eventName IN ('PutPublicAccessBlock', 'DeletePublicAccessBlock', 'PutBucketPublicAccessBlock')    
ORDER BY
	bucketName,
    eventTime DESC
    
/* This query returns Aurora MySQL databases with Instance class information created from beginning of 2022. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'dBInstanceIdentifier' 
    ) as DBInstance, element_at(requestParameters, 'dBInstanceClass' 
    ) as InstanceClass, element_at(requestParameters, 'engine' 
    ) as Engine, eventTime as DateTime
FROM
    $EDS_ID 
WHERE
    element_at(requestParameters, 'engine' 
    ) = 'aurora-mysql'  
    and eventname = 'CreateDBInstance'  
    and eventTime >='2022-01-01 00:00:00'
/* This query results are a list in chronological order of DB reboots that have occured
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    element_at(requestParameters, 'dBInstanceIdentifier'  
    ) as DBInstance, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as RebootTime
FROM
    $EDS_ID 
WHERE
    eventName = 'RebootDBInstance'ORDER BY eventTime DESC
/* 
This query count and group activity based on APIs and the AWS services performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT eventSource, eventName, COUNT(*) AS apiCount 
FROM <EDS ID>
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
GROUP BY eventSource, eventName 
ORDER BY apiCount DESC

/* The following query has a filter for EC2 instance where you can replace <instance id> 
in the below query with your own EC2 instance ID to identity patch compliance status for the specific instance. 
The query has a filter for eventTime as well.  You can search patch compliance status based on specific time ranges.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId,eventData.accountId, eventData.awsRegion, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,
  eventTime
    FROM config_event_data_store_ID
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance' 
  AND replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') = '<instance id such as i-123456789012>'
  AND eventTime > '2023-06-23 00:00:00'
  AND eventTime < '2023-06-25 12:00:00'
) where PatchResult is not null;
/* 
This query creates an athena table named awsconfig. 

Use this query to create a table that can be used to get an aggregated count of AWS Config configuration items. 
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id, and replace LOCATION with path to the bucket where your AWS Config snapshot is delivered.
*/

CREATE EXTERNAL TABLE awsconfig (
	fileversion string,
	configSnapshotId string,
	configurationitems ARRAY < STRUCT < configurationItemVersion: STRING,
	configurationItemCaptureTime: STRING,
	configurationStateId: BIGINT,
	awsAccountId: STRING,
	configurationItemStatus: STRING,
	resourceType: STRING,
	resourceId: STRING,
	resourceName: STRING,
	ARN: STRING,
	awsRegion: STRING,
	availabilityZone: STRING,
	configurationStateMd5Hash: STRING,
	resourceCreationTime: STRING > >
)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
LOCATION 's3://config-bucket-PATH';
/* 
This query obtain successful activity performed by IAM user access key during specific window time grouped by AWS services and API.
Replace <EDS ID> with your Event Data Store Id number and the <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT count (*) as NumberEvents, eventSource, eventName
FROM <EDS ID>
WHERE eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
AND errorcode IS NULL
GROUP by eventSource, eventName
order by NumberEvents desc;

/* 
This query obtain S3 bucket and object names affected by an IAM user access kesy during a specifc window time.
Replace <EDS ID> with your Event Data Store Id number and the <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT element_at(requestParameters, 'bucketName') as BucketName, element_at(requestParameters, 'key') as ObjectName, eventName 
FROM <EDS ID>
WHERE (eventName = 'CopyObject' OR eventName = 'DeleteObject' OR eventName = 'DeleteObjects' OR eventName = 'GetObject' OR eventName = 'HeadObject' OR eventName = 'PutObject') 
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'

/* 
This query helps to confirm which IAM role was assumed by an IAM user access keys during specific window time.
Replace <EDS ID> with your Event Data Store Id number and <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT requestParameters,responseElements
FROM <EDS ID>
WHERE eventName = 'AssumeRole'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE';

/* This query can be used if there are requirements to use only a subsets of AWS regions.  
It lists any events which involve non authorized regions which may help to identify non-compliance scenarios. 
Replace <EDS ID> with your Event Data Store Id number and replace <region>, <accountid> with the desired region and your account id.*/




select
    awsRegion, eventType, eventTime, eventName 
from
    <event_data_store_id> 
where
    awsRegion not in ('region','region' 
    )  
    and recipientAccountId='<accountid>': select
        awsRegion, eventType, eventTime, eventName  
    from
        <event_data_store_id>  
    where
        awsRegion not in ('<region>','<region>' 
        )  
        and recipientAccountId='<accountid>'
/* This query identifies the top callers of the AWS IAM service based on their number of API calls. It
   can help you identity which principals are calling IAM the most and if these principals may be close 
   to service limits.
    
    To use this query, Replace <EDS ID> with your Event Data Store Id.
*/


SELECT
	COUNT(*) AS apiCount, eventName, recipientAccountId, userIdentity.principalid
FROM
	<event_data_store_id> 
WHERE
	userIdentity.principalid IS NOT NULL AND eventTime >= '2022-01-08 00:00:00'
    AND
	    eventSource='iam.amazonaws.com'
GROUP BY
	eventName, recipientAccountId, userIdentity.principalid
ORDER BY
	apiCount DESC


/*This query will show if AWS Support has taken over the AWSServiceRoleForSupport Role, for Data Sovereignty requirements.
Replace <EDS ID> with your Event Data Store Id number.*/


select
    eventTime,  eventSource,  eventName,  awsRegion,  sourceIPAddress, userAgent,  userIdentity.type as userIdtype,  element_at(resources, 1
    ).accountId as ressourceAccountID, element_at(resources, 1
    ).arn as ressourceARN, eventType, eventCategory, managementEvent, recipientAccountId, requestParameters, responseElements 
from
    <EDS ID>
where
    eventSource = 'sts.amazonaws.com' 
    and userAgent = 'support.amazonaws.com'

/* 
This query returns EC2 instances information created across the organization during specific window time.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT recipientAccountId, awsRegion, eventID, element_at(responseElements, 'instancesSet') as instances
FROM <EDS ID>
WHERE eventName='RunInstances'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query confirms if there were any activity performed from IP address in other AWS accounts in your organization except one during specific window time grouped by AWS account.
Replace <EDS ID> with your Event Data Store Id number, the <192.0.2.76> with the IP address you are looking for and the <555555555555> with the AWS account you want to exclude.
*/

SELECT useridentity.accountid 
FROM <EDS ID> 
WHERE sourceIPAddress = '192.0.2.76'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00' 
AND useridentity.accountid != '555555555555' 
GROUP by useridentity.accountid;

/* 
This query returns denied activity based errorCode response and the AWS services performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventSource, eventName, readOnly, errorCode, errorMessage, eventTime, eventID
FROM <EDS ID>
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND (errorCode = 'AccessDenied' OR errorCode LIKE '%Unauthorized%')
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/*

This query provides events with TLS version and event source. This query is helpful when you are trying to find
specific version of TLS. Eg: If you’re trying to find events realted to TLSv1 (which will have a end of support on June 28. 2023),
You can include in the filter criteria AND CAST(REPLACE(tlsDetails.tlsVersion, 'TLSv', '') AS DOUBLE) <= 1.1

This filters all TLS connections with 1.1 and below. Feel free to change the version number on the filter to tilter out 
different versions. You can also change use different operators such as =, >, <, >=, or <= in filtering TLS versions.

*/

SELECT
    eventSource,
    tlsDetails.tlsVersion,
    sourceIPAddress,
    recipientAccountId,
    COUNT(*) AS numOutdatedTlsCalls
FROM
    <event_data_store_id>
WHERE
    eventTime >= '${date_filter}' -- Eg: '2023-06-20 00:00:00'
    AND eventTime <= '${date_filter}' -- Eg: '2023-06-27 00:00:00'
    AND tlsDetails.tlsVersion LIKE 'TLSv%'
    AND CAST(REPLACE(tlsDetails.tlsVersion, 'TLSv', '') AS DOUBLE) <= 1.1
GROUP BY
    eventSource,
    tlsDetails.tlsVersion,
    sourceIPAddress,
    recipientAccountId
ORDER BY
    numOutdatedTlsCalls DESC

/* This query returns results where cross-account access was granted. 
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    userIdentity.principalid, eventName, eventSource, userIdentity.accountId, recipientAccountId, requestParameters, eventTime
FROM
    $EDS_ID 
WHERE
    eventTime > '2022-04-30 00:00:00'  
    AND eventTime < '2022-06-01 00:00:00'  
    AND userIdentity.accountId != recipientAccountId
/* This query modifications to CloudTrail trails.
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    eventName, element_at(requestParameters,'name' 
    ), userIdentity.principalid, eventTime
FROM
    $EDS_ID 
WHERE
    eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'  
    AND ( eventName = 'CreateTrail'  
        or eventName = 'UpdateTrail'  
        or eventName = 'DeleteTrail'  
        or eventName = 'StartLogging'  
        or eventName = 'StopLogging'  
    )
/* This query returns Aurora Postgresql DB instances that have performance insights enabled
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'dBInstanceIdentifier' 
    ) as DBInstance, element_at(requestParameters, 'engine' 
    ) as Engine, element_at(requestParameters, 'engineVersion' 
    ) as DBEngineVersion
FROM
    $EDS_ID 
WHERE
    element_at(requestParameters, 'engine' 
    ) = 'aurora-postgresql'  
    and eventname = 'CreateDBInstance' 
    and element_at(requestParameters, 'enablePerformanceInsights' 
    ) = 'true'
/* This query analyzes CloudTrail Events and identifies any calls that result in errors.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.arn,eventTime,eventSource,eventName,awsRegion,sourceIPAddress,userAgent,errorCode,errorMessage,requestParameters,readOnly,resources,recipientAccountId,tlsDetails
FROM
    <event-data-store-ID>
WHERE
    errorCode IS NOT NULL  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'
/* 
This query count activity performed by an IAM role during specific time period grouped by AWS services and APIs.
Replace <EDS ID> with your Event Data Store Id number and the <arn:aws:iam::555555555555:role/alice> with the IAM role ARN.
*/

SELECT count (*) as NumberEvents, eventSource, eventName
FROM <EDS ID> 
WHERE eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00' 
AND useridentity.type = 'AssumedRole' 
AND useridentity.sessioncontext.sessionissuer.arn = 'arn:aws:iam::555555555555:role/alice'
GROUP by eventSource, eventName
order by NumberEvents desc;

/*

This query returns ec2 security groups with rules that allow public (0.0.0.0/0) access. This query is useful
when you are trying to audit and investigate security groups allowing public access.

Notice that there are two queries below that are being combined using the 'UNION ALL' clause. 

The first query pulls the AuthorizeSecurityGroupIngress events (for newly created security group rules).
The 2nd query pulls the ModifySecurityGroupRulesRequest (for modification on security group rules).

*/

-- This part of the query returns AuthorizeSecurityGroupIngress events
SELECT
    eventName,
    userIdentity.arn AS user,
    sourceIPAddress,
    eventTime,
    eventSource,
    element_at(requestParameters, 'groupId') AS securityGroup,
    element_at(requestParameters, 'ipPermissions') AS securityGroupRule
FROM
    <event_data_store_id>
WHERE
    eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-08 00:00:00'
    AND eventName = 'AuthorizeSecurityGroupIngress'    
    AND element_at(requestParameters, 'ipPermissions') LIKE '%0.0.0.0/0%' -- this filter is used to find security group changes with public rules.

UNION ALL

-- This part of the query returns ModifySecurityGroupRulesRequest events
SELECT
    eventName,
    userIdentity.arn AS user,
    sourceIPAddress,
    eventTime,
    eventSource,
    json_extract_scalar(element_at(requestParameters, 'ModifySecurityGroupRulesRequest'), '$.GroupId') securityGroup,
    element_at(requestParameters, 'ModifySecurityGroupRulesRequest') securityGroupRule    
FROM
    <event_data_store_id>
WHERE
	eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-09 00:00:00'
	AND eventName = 'ModifySecurityGroupRules'
    AND element_at(requestParameters, 'ModifySecurityGroupRulesRequest') LIKE '%0.0.0.0/0%'  -- this filter is used to find security group changes with public rules.
ORDER
    BY eventTime DESC
/* This query returns snapshots that are created which are not encrypted.  
Replace <EDS ID> with your Event Data Store Id number.
*/


select
    userIdentity.principalid,awsRegion,element_at(requestParameters,'volumeId'  
    ) as volume, json_extract(element_at(requestparameters, 'CreateSnapshotsRequest'  
        ),'$.InstanceSpecification.InstanceId'  
    ) as Instance, element_at(responseElements,'snapshotId'  
    ) as snapshotID 
from
    $EDS_ID
where
    eventName like '%CreateSnapshots%'  
    or eventName like '%CreateSnapshot'  
    and element_at(responseElements,'encrypted'  
    )='false'  
    and eventTime < '2022-01-01 00:00:00'  
    and eventTime > '2022-11-11 00:00:00' 
/* 
This query returns the amount of times an AWS Config rule has been evaluated.

Use this query to Get a total count for the number of times AWS Config rules have been evaluated. 
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT
    count(*
    ) as TotalEvents, date(eventTime
    ) as datestamp,awsRegion, recipientAccountId, element_at(additionalEventData, 'configRuleName'
    ) as configRuleName, element_at(additionalEventData, 'configRuleArn'
    ) as configRuleArn
FROM 
<event_data_store_id>
WHERE
    eventName= 'PutEvaluations'
    and eventTime > '2022-11-01 00:00:00'
    AND eventTime < '2022-11-22 00:00:00'
group
    by date(eventTime
    ), awsRegion, recipientAccountId, additionalEventData
order 
	by date(eventTime
    ) desc, TotalEvents desc, recipientAccountId
/* This query returns tag history for resources.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    awsRegion, eventSource, json_extract_scalar(eventjson, '$.requestParameters.resourcesSet.items[0].resourceId' 
    ) as resourceId, eventTime, eventName, json_extract_scalar(eventjson, '$.requestParameters.tagSet.items[0].key' 
    ) as key, json_extract_scalar(eventjson, '$.requestParameters.tagSet.items[0].value' 
    ) as value, useridentity.arn as identityarn 
from
    $EDS_ID 
where
    eventTime > '2022-01-01 00:00:00'  
    and eventName in ('CreateTags','DeleteTags' 
    )order by resourceId,key,eventTime desc
/* The following query has a filter for EC2 instance where you can replace <instance id> 
in the below query with your own EC2 instance ID to identity patch compliance status for the specific instance.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId,eventData.accountId, eventData.awsRegion, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,
  eventTime
    FROM config_event_data_store_ID 
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance' 
  AND replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') = '<instance id such as i-123456789012>'
) where PatchResult is not null;
/* This query returns the most retrieved S3 Objects.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'bucketName'
    ) as bucketName,  element_at(requestParameters, 'key'
    ) as key,  COUNT(*
    ) as requestCount 
FROM
    $EDS_ID 
WHERE
    eventSource = 's3.amazonaws.com'  
    AND eventCategory = 'Data'  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'  
    AND eventName = 'GetObject' 
GROUP
    BY requestParameters ORDER BY requestCount DESC LIMIT 20;
/* 
This query returns IAM Identity Center users who has authenticated into IAM Identity Center portal during specific window time.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT userIdentity.username, eventTime, recipientAccountId, awsRegion, sourceIPAddress, eventID
FROM FROM <EDS ID>
WHERE eventSource = 'sso.amazonaws.com'
AND eventName = 'Authenticate'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* This query lists the top Error messages for the specified time range
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    errorCode,  errorMessage,  COUNT(*
    ) as eventCount
FROM
    $EDS_ID
WHERE
    eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND (errorCode is not null 
        or errorMessage is not null
    )
GROUP
    BY errorCode, errorMessageORDER BY eventCount DESCLIMIT 10;
/* This query returns when some user was made admin and who did it (added to any groups with name containing word ‘admin’). Helps identifying privilege escalation related issues.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.principalid, eventName, eventTime, element_at(requestParameters,'userName'  
    ) AS username, element_at(requestParameters,'groupName'  
    ) AS groupname
FROM
    $EDS_ID
WHERE
    eventTime > '2022-04-30 00:00:00'  
    AND eventTime < '2022-11-01 00:00:00'  
    AND eventName = 'AddUserToGroup'  
    AND element_at(requestParameters,'groupName'  
    ) like '%admin%'
/* The below query returns the list of instances without returning duplicate instance IDs. 
The latest EC2 compliance data are returned. By default, CloudTrail Lake query can return 
multiple EC2 instance compliance data because Config keeps track of historical data.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  eventData.accountId, eventData.awsRegion, replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId, eventTime, 
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,eventTime, rank() over (partition by replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') order by eventTime desc) as rnk
    FROM config_event_data_store_ID
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance'
) where rnk = 1
/* This query Shows wich identity is making the most GetObject requests from S3 and what it is downloading, including error detail and attempted unauthorized accesses.
Replace <EDS ID> with your Event Data Store Id number.*/

SELECT
    userIdentity.principalId, errorMessage, element_at(requestParameters, 'bucketName' 
    ) as bucket, element_at(requestParameters, 'key' 
    ) as objectKey, count(* 
    ) as attempts
FROM
    <event_data_store_id> 
WHERE
    eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-30 00:00:00'  
    AND eventSource = 's3.amazonaws.com' 
    AND eventName = 'GetObject'
GROUP
    BY userIdentity.principalId, errorMessage, requestParametersORDER BY attempts desc
/* This query lists the encryption status of Objects uploaded to S3 buckets in the descending order of event time.
Replace <EDS ID> with your Event Data Store Id number.*/

/*Pre-reqs:
Activate data events for S3 and perform upload operations in the S3 bucket which has encryption enabled/disabled and upload object with encryption enabled/disabled. 
*/

select
    recipientAccountId, eventTime, element_at(requestParameters,'bucketName'
    ) AS S3BUCKET , element_at(requestParameters,'key'
    ) AS S3OBJECT, element_at(requestParameters,'x-amz-server-side-encryption'
    ) AS ReqENCRYPTION,element_at(responseElements,'x-amz-server-side-encryption'
    ) AS RespENCRYPTION 
from
    $EDS_ID 
where
    eventName='PutObject' order by eventTime desc
/* This query returns console logins with no MFA. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'signin.amazonaws.com'  
    AND eventname = 'ConsoleLogin'  
    AND Element_at(additionaleventdata, 'MFAUsed' 
    ) = 'No'
/* 
This query helps to confirm successful activity performed by IAM role during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the <arn:aws:iam::555555555555:role/alice> with the IAM role ARN.
*/

SELECT eventSource, eventName, eventTime, eventID, errorCode 
FROM <EDS ID> 
WHERE eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND useridentity.type = 'AssumedRole'
AND useridentity.sessioncontext.sessionissuer.arn = 'arn:aws:iam::555555555555:role/alice';

/* This query identifies roles that are assuming themselves.

Roles assuming themselves are typically the result of unnecessary operations in code
Self assume role events count towards the STS quota.
    
    To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/


SELECT
    eventid, eventtime, userIdentity.sessioncontext.sessionissuer.arn as RoleARN, userIdentity.principalId as RoleIdColonRoleSessionName 
from
    <event_data_store_id> 
where
    eventSource = 'sts.amazonaws.com' 
    and eventName = 'AssumeRole' 
    and userIdentity.type = 'AssumedRole' 
    and errorcode IS NULL 
    and userIdentity.sessioncontext.sessionissuer.arn = element_at(resources,1
    ).arn

/* This query returns database failover information: Returns Region, DB, user, and time of a failover event for a database
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    awsRegion as AWSRegion,  element_at(requestParameters, 'dBClusterIdentifier'
    ) as DBCluster, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as FailoverTime
FROM
    $EDS_ID 
WHERE
    eventName = 'FailoverDBCluster'
/* 
This query returns information about API IAM PutRolePolicy called by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, eventID, eventTime, element_at(requestParameters, 'roleName') as roleName, element_at(requestParameters, 'policyDocument') as policyDocument 
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='PutRolePolicy'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/*This query gets a list of all resources that have been created manually (i.e outside of CloudFormation or via set list of CI/CD users), along with details on the action taken. 
Replace <EDS ID> with your Event Data Store Id number.*/

SELECT
    userIdentity.arn AS user, userIdentity, eventTime, eventSource, eventName, awsRegion, requestParameters, resources, requestID, eventID
FROM
    <EDS ID>
WHERE
    (eventName LIKE '%Create%' 
        OR eventName LIKE '%Update%' 
        OR eventName LIKE '%Put%' 
        OR eventName LIKE '%Delete%'
    )
    AND resources IS NOT NULL
    AND userIdentity.sessioncontext.sessionissuer.username NOT LIKE 'AWSServiceRole%'
    AND userIdentity.sessioncontext.sessionissuer.username NOT IN (''
    )
    AND sourceIpAddress != 'cloudformation.amazonaws.com'ORDER BY eventTime DESC
/* 
This query obtain response element for a given CloudTrail event Id.
Replace <EDS ID> with your Event Data Store Id number and the CloudTrail event Id <3270e016-59a1-4448-8dd1-d27a4796502d>
*/

SELECT responseElements
FROM <EDS ID>
WHERE eventID = '3270e016-59a1-4448-8dd1-d27a4796502d';

/* This query shows counts of all Data events by Day of the Week. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    day_of_week(eventTime
    ) as weekday,  COUNT(*
    ) as eventCount
FROM
    $EDS_ID
WHERE
    eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND eventCategory = 'Data'
GROUP
    BY day_of_week(eventTime
    )ORDER BY day_of_week(eventTime
    )
/* The following query run against all EC2 instances to identity patch compliance status. 
The query has a filter for eventTime as well.  You can search patch compliance status based on specific time ranges.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId,eventData.accountId, eventData.awsRegion, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,
  eventTime
    FROM config_event_data_store_ID
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance' 
  AND eventTime > '2023-06-23 00:00:00'
  AND eventTime < '2023-06-25 12:00:00'
) where PatchResult is not null;
/* This query shows all API requests where the specified TLS version was not used.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    eventName,  awsRegion,  sourceIPAddress,  recipientAccountId,  tlsDetails.tlsversion
FROM
    $EDS_ID
WHERE
    eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND tlsDetails.tlsversion != 'TLSv1.3'

/* This query identifies buckets across an Organization with requests that rely on ACLs. This can help when migrating away from legacy ACLs to IAM Policies.

Replace <EDS ID> with your Event Data Store ID number.
*/

SELECT DISTINCT
    element_at(requestParameters, 'bucketName') AS Bucket,
    awsRegion AS Region,
    recipientAccountId AS AccountID
FROM
    <EDS_ID> 
WHERE
    element_at(additionalEventData, 'aclRequired') = 'Yes'
ORDER BY
    recipientAccountId,
    awsRegion
/* 
This query returns the estimated amount of Configuration items per resource type.

Use this query to estimate the cost of the AWS Config recorder.  
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT
    recipientAccountId, awsRegion, eventSource, count(* 
    ) as TotalPossibleCI 
FROM
    <event_data_store_id>
Where
    (eventSource like 'eks%' 
        or eventSource like 'ec2%' 
        or eventSource like 'vpc%'
        or eventSource like 'ecs%' 
        or eventSource like 'iam%' 
        or eventSource like 'autoscaling%' 
        or eventSource like 's3%' 
        or eventSource like 'rds%' 
        or eventSource like 'backup%' 
        or eventSource like 'athena%' 
        or eventSource like 'cloudtrail%' 
        or eventSource like 'cloudfront%' 
        or eventSource like 'cloudformation%' 
        or eventSource like 'code%' 
        or eventSource like 'ecr%' 
        or eventSource like 'lambda%' 
        or eventSource like 'efs%' 
    ) 
    and readOnly=False 
    and managementEvent=True 
    and eventTime > '2023-10-01 00:00:00' 
    AND eventTime < '2023-10-30 00:00:00' 
group
    by recipientAccountId, awsRegion, eventSource Order by recipientAccountId desc, TotalPossibleCI desc
/* This query returns source and target of an RDS point in time restore
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'sourceDBClusterIdentifier' 
    ) as Source, element_at(requestParameters, 'dBClusterIdentifier' 
    ) as Target, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as RestoreTime
FROM
    $EDS_ID 
WHERE
    eventName = 'RestoreDBClusterToPointInTime'
/* The SQL query will be run against the configuration items that been collected from the resource type, 
AWS::SSM::PatchCompliance, as part of the config rule ec2-managedinstance-patch-compliance-status-check.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  eventData.accountId, eventData.awsRegion, replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,eventTime
    FROM config_event_data_store_ID 
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance'
) where PatchResult is not null
/* This query analyzes CloudTrail Events and identifies any calls that are made to AWS service APIs via the AWS Management Console.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.arn,eventTime,eventSource,eventName,awsRegion,sourceIPAddress,userAgent,requestParameters,readOnly,recipientAccountId,sessionCredentialFromConsole
FROM
    <event-data-store-ID>
WHERE
    sessionCredentialFromConsole = true  
    AND readOnly = false  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'
/* 
This query will query the table created by ConfigTableCreation.sql to get an aggregated count of Configuration Items. 

Use this query to understand how many changes have happened on each resource type and resourceID. 
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT configurationItem.resourceType,
	configurationItem.resourceId,
	COUNT(configurationItem.resourceId) AS NumberOfChanges
FROM default.awsconfig
	CROSS JOIN UNNEST(configurationitems) AS t(configurationItem)
WHERE '$path' LIKE '%ConfigHistory%'
	AND configurationItem.configurationItemCaptureTime >= '2023-11-01T%'
	AND configurationItem.configurationItemCaptureTime <= '2023-11-21T%'
GROUP BY configurationItem.resourceType,
	configurationItem.resourceId
ORDER BY NumberOfChanges DESC

/*
Find all principal IDs who called a particular API on a particular day.
*/

SELECT userIdentity.arn AS user, eventName FROM $EDS_ID WHERE userIdentity.arn IS NOT NULL AND eventName='CreateBucket' AND eventTime > '2024-06-26 00:00:00' AND eventTime < '2024-06-27 00:00:00'

/*
Find all the APIs that a particular user called in a specified date range.
*/

SELECT eventID, eventName, eventSource, eventTime, userIdentity.arn AS user FROM $EDS_ID WHERE userIdentity.arn LIKE '%<username>%' AND eventTime > '2024-06-26 00:00:00' AND eventTime < '2024-06-29 00:00:00'

/*
Find the number of API calls grouped by event name and event source within the past week
*/

SELECT eventSource, eventName, COUNT(*) AS apiCount FROM $EDS_ID WHERE eventTime > '2024-06-26 00:00:00' GROUP BY eventSource, eventName ORDER BY apiCount DESC

/*
Find all users who logged into the console from a set of regions within the past week.
*/

SELECT eventTime, userIdentity.arn AS user, awsRegion FROM $EDS_ID WHERE awsRegion in ('us-east-1', 'us-west-2') AND eventName = 'ConsoleLogin' AND eventTime > '2024-06-26 00:00:00'

/*
Find all the CloudTrail queries that were ran within the past week.
*/

SELECT element_at(responseElements, 'queryId'), element_at(requestParameters, 'queryStatement') FROM $EDS_ID WHERE eventName='StartQuery' AND eventSource = 'cloudtrail.amazonaws.com' AND responseElements IS NOT NULL AND eventTime > '2024-06-26 00:00:00'

/*
Find users who signed in to the console the most within the past week.
*/

SELECT userIdentity.arn, COUNT(*) AS loginCount FROM $EDS_ID WHERE eventName = 'ConsoleLogin' AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn ORDER BY count(*) DESC

/*
Find all PutObject calls for a particular S3 bucket within the past week.
*/

SELECT requestParameters FROM $EDS_ID WHERE userIdentity.arn IS NOT NULL AND eventName='PutObject' AND element_at(requestParameters, 'bucketName') = 'bucketnamehere' AND eventTime > '2024-06-26 00:00:00'

/*
Filter out resources by matching ARN values within the past week.
*/

SELECT resources FROM $EDS_ID WHERE element_at(resources, 1).arn LIKE '%<resource ARN>%' AND eventTime > '2024-06-26 00:00:00'

/*
Query the event data store over the past month to rank the number of events ingested each day.
*/
SELECT date_trunc('day', eventtime), COUNT(*) AS eventCount FROM $EDS_ID WHERE eventTime > '2024-06-03 00:00:00' GROUP BY date_trunc('day', eventtime) ORDER BY count(*) DESC

/*
Find the number of calls per service that used the outdated Transport Layer Security (TLS) versions 1.0 and 1.1 within the past week.
*/

SELECT eventSource, COUNT(*) AS numOutdatedTlsCalls FROM $EDS_ID WHERE tlsDetails.tlsVersion IN ('TLSv1', 'TLSv1.1') AND eventTime > '2024-06-26 00:00:00' GROUP BY eventSource ORDER BY numOutdatedTlsCalls DESC

/*
Find the callers who used outdated Transport Layer Security (TLS) versions 1.0 and 1.1 within the past week grouped by the number of calls per service.
*/

SELECT recipientAccountId, year(eventTime) AS year_date, month(eventTime) AS month_date, eventSource, sourceIPAddress, userAgent, userIdentity.arn, userIdentity.accesskeyid, COUNT(*) AS numCalls FROM $EDS_ID WHERE tlsDetails.tlsVersion IN ('TLSv1', 'TLSv1.1') AND eventTime > '2024-06-26 00:00:00' GROUP BY recipientAccountId, year(eventTime), month(eventTime), eventSource, sourceIPAddress, userAgent, userIdentity.arn, userIdentity.accesskeyid ORDER BY COUNT(*) DESC

/*
Find users with write permissions who made changes using the console within the past week.
*/

SELECT userIdentity.arn AS user, eventName, eventTime, awsRegion, requestParameters AS resourceChangedManually FROM $EDS_ID WHERE sessionCredentialFromConsole='true' AND errorCode IS NULL AND eventTime > '2024-06-26 00:00:00'

/*
Find users who logged into the running container and ran commands within the past week.
*/

SELECT userIdentity.arn AS user, element_at(requestParameters, 'container') AS container, element_at(requestParameters, 'command') AS command, eventTime FROM $EDS_ID WHERE eventSource='ecs.amazon.com' AND eventName='ExecuteCommand' AND eventTime > '2024-06-26 00:00:00'

/*
Find security group changes made within the past week.
*/

SELECT eventName, userIdentity.arn AS user, sourceIPAddress, eventTime, element_at(requestParameters, 'groupId') AS securityGroup, element_at(requestParameters, 'ipPermissions') AS ipPermissions FROM $EDS_ID WHERE (element_at(requestParameters, 'groupId') LIKE '%sg-%') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime ASC

/*
Find all security group and network ACL changes within the past week.
*/

SELECT * FROM $EDS_ID WHERE ((eventName LIKE '%SecurityGroup%' OR eventName LIKE '%NetworkAcl%') AND eventName NOT LIKE 'Describe%') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime ASC

/*
Find all service limits increased across different regions and accounts within the past week.
*/

SELECT userIdentity.arn AS user, awsRegion, element_at(serviceEventDetails, 'serviceName') AS ServiceName, element_at(serviceEventDetails, 'quotaName') AS QuotaName, element_at(serviceEventDetails, 'createTime') AS RequestedOn, element_at(serviceEventDetails, 'newQuotaValue') AS NewLimitValue, element_at(serviceEventDetails, 'newStatus') AS Status FROM $EDS_ID WHERE eventSource='servicequotas.amazonaws.com' AND eventName in ('UpdateServiceQuotaIncreaseRequestStatus', 'RequestServiceQuotaIncrease') AND element_at(serviceEventDetails, 'serviceName') != '' AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime ASC

/*
Find all manually created resources within the past week.
*/

SELECT userIdentity.arn AS user, userIdentity, eventTime, eventSource, eventName, awsRegion, requestParameters, resources, requestID, eventID FROM $EDS_ID WHERE (eventName LIKE '%Create%') AND resources IS NOT NULL AND userIdentity.sessioncontext.sessionissuer.username NOT LIKE 'AWSServiceRole%' AND userIdentity.sessioncontext.sessionissuer.username IS NOT NULL AND sourceIpAddress != 'cloudformation.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find all users who accessed a given database and table within the past week and show whether access was successful as configured in LakeFormation.
*/

SELECT eventSource, eventName, userIdentity.arn AS user, element_at(requestParameters, 'databaseName') AS DatabaseName, element_at(requestParameters, 'name') AS TableName, json_array_contains(json_parse(element_at(additionalEventData, 'insufficientLakeFormationPermissions')),'<DatabaseName>:<Table Name>') AS FailedAccess, eventTime FROM $EDS_ID WHERE eventSource ='glue.amazonaws.com' AND element_at(requestParameters, 'databaseName') = '<Database Name>' AND element_at(requestParameters, 'name') = '<Table Name>' AND element_at(additionalEventData, 'lakeFormationPrincipal') != '<ARN of Data Lake Admin Role>' AND eventTime > '2024-06-26 00:00:00'

/*
Find all Glue databases and tables viewed or modified by a given database administrator within the past week.
*/

SELECT element_at(requestParameters, 'databaseName') AS DatabaseName, element_at(requestParameters, 'name') AS TableName, eventName, userIdentity.arn AS user FROM $EDS_ID WHERE eventSource ='glue.amazonaws.com' AND element_at(requestParameters, 'databaseName') IS NOT NULL AND element_at(requestParameters, 'name') IS NOT NULL AND element_at(additionalEventData, 'lakeFormationPrincipal') != '<ARN of Data Lake Admin>' AND eventTime > '2024-06-26 00:00:00' 

/*
Find all active S3 objects for the past week.
*/

SELECT accountid, eventName, eventTime, replace(resourceArn, 'arn:aws:s3:::') as s3Resource, useragent FROM $EDS_ID t CROSS JOIN UNNEST(t.resources) unnested (accountid, resourceType, resourceArn, resourceArnPrefix) WHERE eventSource='s3.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' 

/*
Find the records of all API activities performed with the matching accessKeyId.
*/

SELECT eventTime, eventName, userIdentity.principalId FROM $EDS_ID WHERE userIdentity.accessKeyId LIKE '<accessKeyId>' AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find all unsuccessful console sign-in attempts.
*/

SELECT sourceipaddress, useridentity.arn, errorMessage, additionaleventdata FROM $EDS_ID WHERE eventname = 'ConsoleLogin' AND errorMessage IS NOT NULL AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find all API events that failed due to missing permissions.
*/

SELECT count (*) as TotalEvents, eventsource, eventname, useridentity.arn, errorCode, errorMessage FROM $EDS_ID WHERE (errorcode like '%Denied%' or errorcode like '%Unauthorized%') AND eventTime > '2024-06-26 00:00:00' GROUP BY eventsource, eventname, errorCode, errorMessage, useridentity.arn ORDER BY eventsource, eventname

/*
Find the events that increased your CloudTrail bill.
*/
SELECT eventName, count(eventName) AS apiCallCount, eventSource FROM $EDS_ID WHERE eventTime > '2024-06-03 00:00:00' GROUP BY eventName, eventSource ORDER BY apiCallCount DESC 

/*
Find all PutObject requests sorted by bytesTransferredIn in descending order.
*/

SELECT element_at(requestParameters, 'bucketName') AS s3BucketName, cast(element_at(additionalEventData, 'bytesTransferredIn') AS int) AS bytesTransferredIn FROM $EDS_ID WHERE eventName='PutObject' AND eventTime > '2024-06-26 00:00:00' ORDER BY bytesTransferredIn DESC 

/*
Find all events across multiple event data stores using UNION ALL.
*/

SELECT eventsource, eventname, eventtime FROM $EDS_ID WHERE eventTime > date_add('day', -QUERY_TIME_RANGE_IN_DAYS.WEEKLY, now()) UNION ALL SELECT eventData.eventsource, eventData.eventname, eventData.eventtime FROM $INTEGRATION_EDS_ID WHERE eventData.eventtime > date_add('day', -QUERY_TIME_RANGE_IN_DAYS.WEEKLY, now())

/*
Find all the buckets that haven't been accessed for more than a year.
*/

SELECT element_at(requestParameters, 'bucketName') AS bucketName, max(eventtime) AS lastActivityTime FROM $EDS_ID WHERE eventSource='s3.amazonaws.com' AND element_at(requestParameters, 'bucketName') IS NOT NULL GROUP BY 1 HAVING max(eventTime) < date_add('day', -365, now()) 

/*
Find all EC2 events for the past 3 days.
*/

SELECT eventName, eventTime, element_at(requestParameters, 'name') AS TableName, userIdentity.principalId FROM $EDS_ID WHERE eventSource='ec2.amazonaws.com' AND eventTime > date_add('day', -3, now())

/*
Find the catalog name for all Athena StartQuery requests
*/

SELECT eventTime, json_extract(element_at(requestParameters, 'queryExecutionContext'), '$.catalog') as catalog FROM $EDS_ID WHERE eventSource='athena.amazonaws.com' AND eventName='StartQueryExecution' AND eventTime > '2024-06-26 00:00:00'

/*
Find all S3 requests that accessed the AWSLogs prefix of S3Buckets.
*/

SELECT element_at(requestParameters, 'bucketName') as s3BucketName, eventName, useridentity.arn FROM $EDS_ID WHERE regexp_like(element_at(requestParameters, 'key'), 'AWSLogs') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'bucketName'), eventName, useridentity.arn

/*
Find the usage of all events by part of the globe.
*/

SELECT substr(awsRegion, 1, 2) AS globalCode, count(*) AS totalNumberOfEvents FROM $EDS_ID WHERE eventTime > '2024-06-26 00:00:00' GROUP BY 1 ORDER BY totalNumberOfEvents DESC 

/*
List all the IAM roles assumed to access services.
*/

SELECT eventSource, array_agg(distinct userIdentity.arn) as AssumedRoles FROM $EDS_ID WHERE userIdentity.arn IS NOT NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY eventSource

/*
Find all actions in IAM policies.
*/

SELECT flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar)))) as actions FROM $EDS_ID WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'sts%' OR eventSource like 'iam%') AND eventTime > '2024-06-26 00:00:00'

/*
Find the users who made the most failed API calls within the past week.
*/

SELECT userIdentity.arn as user, COUNT(*) AS error_count FROM $EDS_ID WHERE errorCode IS NOT NULL AND userIdentity.arn IS NOT NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn ORDER BY error_count DESC LIMIT 10

/*
Find the IAM actions used in the most created IAM policies.
*/

SELECT action, count(*) as iamActionUsageCount FROM $EDS_ID CROSS JOIN UNNEST(flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar))))) as t (action) WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'iam%') AND eventName = 'CreatePolicy' AND eventTime > '2024-06-26 00:00:00' GROUP BY action ORDER BY iamActionUsageCount DESC

/*
Find the AWS services used in the most created IAM policies.
*/

SELECT element_at(split(action, ':'), 1) as awsService, count(*) as numberOfServiceActions FROM $EDS_ID CROSS JOIN UNNEST(flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar))))) as t (action) WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'iam%') AND eventName = 'CreatePolicy' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(split(action, ':'), 1) ORDER BY count(*) DESC

/*
Find the least recently used IAM roles.
*/

SELECT coalesce(element_at(requestParameters, 'roleName'), element_at(requestParameters, 'roleArn')) as roleName, max(eventTime) as lastUsage FROM $EDS_ID WHERE eventSource in ('sts.amazonaws.com', 'iam.amazonaws.com') AND eventTime > '2024-06-26 00:00:00' GROUP BY coalesce(element_at(requestParameters, 'roleName'), element_at(requestParameters, 'roleArn')) ORDER BY lastUsage ASC

/*
Find the least recently assumed IAM roles.
*/

SELECT element_at(requestParameters, 'roleArn') as roleArn, max(eventTime) as lastUsage FROM $EDS_ID WHERE eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'roleArn') ORDER BY lastUsage ASC

/*
Find the most frequently assumed IAM roles.
*/
SELECT element_at(requestParameters, 'roleArn') as roleArn, count(*) as timesAssumed FROM $EDS_ID WHERE eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'roleArn') ORDER BY timesAssumed DESC

/*
Find principal IDs whose AssumeRole calls failed.
*/

SELECT userIdentity.arn as callerRole, element_at(split(errorMessage, 'not authorized to perform: sts:AssumeRole on resource: '), 2) as failedToAssume FROM $EDS_ID WHERE eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole' AND errorCode = 'AccessDenied' AND eventTime > '2024-06-26 00:00:00'

/*
Find the users who have turned off multi-factor authentication.
*/

SELECT userIdentity.arn, userIdentity.userName, userIdentity.accountId, useridentity.principalId FROM $EDS_ID WHERE eventSource = 'iam.amazonaws.com' AND eventName in ('DeactivateMFADevice', 'DeleteVirtualMFADevice') AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn, userIdentity.userName, userIdentity.accountId, useridentity.principalId

/*
Find the users who haven't changed their passwords recently.
*/

SELECT userIdentity.arn, userIdentity.userName, userIdentity.accountId, max(eventTime) as lastPasswordChange FROM $EDS_ID WHERE eventName = 'ChangePassword' AND errorCode is NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn, userIdentity.userName, userIdentity.accountId ORDER BY lastPasswordChange ASC

/*
Find all IAM user and role deletions in the past week.
*/

SELECT eventtime AS deletion_time, useridentity.username AS deleted_identity, useridentity.type AS identity_type FROM $EDS_ID WHERE (eventname = 'DeleteUser' AND useridentity.type = 'IAMUser') OR (eventname = 'DeleteRole' AND useridentity.type = 'Role') AND eventTime > '2024-06-26 00:00:00'

/*
Find assume role calls within the same account.
*/

SELECT * FROM $EDS_ID WHERE eventName = 'AssumeRole' AND element_at(split(element_at(requestParameters, 'roleArn'), ':'), 5) = element_at(split(useridentity.arn, ':'), 5) AND eventTime > '2024-06-26 00:00:00'

/*
Find accounts making assume role calls.
*/

SELECT useridentity.accountId, count(*) as numberOfAssumeRoleCalls FROM $EDS_ID WHERE eventName = 'AssumeRole' AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.accountId ORDER BY numberOfAssumeRoleCalls DESC

/*
Identify when IAM access keys were created, who created them on a particular day.
*/

SELECT * FROM $EDS_ID WHERE eventName = 'CreateAccessKey' AND eventTime > '2024-06-26 00:00:00'

/*
Find users who created access keys.
*/

SELECT userIdentity.arn, userIdentity.userName, userIdentity.accountId, count(*) as accessKeyCreationCalls FROM $EDS_ID WHERE eventName = 'CreateAccessKey' AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn, userIdentity.userName, userIdentity.accountId ORDER BY accessKeyCreationCalls DESC

/*
Find IAM changes that modify access to actions that can be used for privilege escalation.
*/

SELECT events.* FROM $EDS_ID as events CROSS JOIN UNNEST(flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar))))) as t (action) WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'sts%' OR eventSource like 'iam%') AND action IN ('iam:AddRoleToInstanceProfile', 'iam:AddUserToGroup', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy', 'iam:AttachUserPolicy', 'iam:CreateAccessKey', 'iam:CreatePolicyVersion', 'iam:CreateRole', 'iam:DeleteRolePolicy', 'iam:DeleteUserPolicy', 'iam:DetachGroupPolicy', 'iam:DetachRolePolicy', 'iam:DetachUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy', 'iam:PutUserPolicy', 'iam:RemoveUserFromGroup', 'iam:SetDefaultPolicyVersion', 'iam:UpdateUser', 'sts:AssumeRole') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find API actions matching an IAM action-level statement.
*/

SELECT eventId, useridentity FROM $EDS_ID CROSS JOIN (VALUES '{"Sid": "Statement1","Effect": "Allow","Action": ["service1:ApiName","service2:*"],"Resource": "*"}') as iam (stmt) WHERE (contains(cast(json_extract(stmt, '$.Action') as array(varchar)), concat(element_at(split(eventsource, '.'), 1), ':', eventName)) OR contains(cast(json_extract(stmt, '$.Action') as array(varchar)), concat(element_at(split(eventsource, '.'), 1), ':*'))) AND cast(json_extract(stmt, '$.Effect') as varchar) = 'Allow' AND eventTime > '2024-06-26 00:00:00'

/*
Find AWS console sign-in events without multi-factor authentication.
*/

SELECT * FROM $EDS_ID WHERE eventName = 'ConsoleLogin' AND cast(useridentity.sessioncontext.attributes.mfaauthenticated as boolean) = false AND eventTime > '2024-06-26 00:00:00'


/*
Find all principal IDs who called a particular API on a particular day.
*/

SELECT userIdentity.arn AS user, eventName FROM $EDS_ID WHERE userIdentity.arn IS NOT NULL AND eventName='CreateBucket' AND eventTime > '2024-06-26 00:00:00' AND eventTime < '2024-06-27 00:00:00'

/*
Find all the APIs that a particular user called in a specified date range.
*/

SELECT eventID, eventName, eventSource, eventTime, userIdentity.arn AS user FROM $EDS_ID WHERE userIdentity.arn LIKE '%<username>%' AND eventTime > '2024-06-26 00:00:00' AND eventTime < '2024-06-29 00:00:00'

/*
Find the number of API calls grouped by event name and event source within the past week
*/

SELECT eventSource, eventName, COUNT(*) AS apiCount FROM $EDS_ID WHERE eventTime > '2024-06-26 00:00:00' GROUP BY eventSource, eventName ORDER BY apiCount DESC

/*
Find all users who logged into the console from a set of regions within the past week.
*/

SELECT eventTime, userIdentity.arn AS user, awsRegion FROM $EDS_ID WHERE awsRegion in ('us-east-1', 'us-west-2') AND eventName = 'ConsoleLogin' AND eventTime > '2024-06-26 00:00:00'

/*
Find all the CloudTrail queries that were ran within the past week.
*/

SELECT element_at(responseElements, 'queryId'), element_at(requestParameters, 'queryStatement') FROM $EDS_ID WHERE eventName='StartQuery' AND eventSource = 'cloudtrail.amazonaws.com' AND responseElements IS NOT NULL AND eventTime > '2024-06-26 00:00:00'

/*
Find users who signed in to the console the most within the past week.
*/

SELECT userIdentity.arn, COUNT(*) AS loginCount FROM $EDS_ID WHERE eventName = 'ConsoleLogin' AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn ORDER BY count(*) DESC

/*
Find all PutObject calls for a particular S3 bucket within the past week.
*/

SELECT requestParameters FROM $EDS_ID WHERE userIdentity.arn IS NOT NULL AND eventName='PutObject' AND element_at(requestParameters, 'bucketName') = 'bucketnamehere' AND eventTime > '2024-06-26 00:00:00'

/*
Filter out resources by matching ARN values within the past week.
*/

SELECT resources FROM $EDS_ID WHERE element_at(resources, 1).arn LIKE '%<resource ARN>%' AND eventTime > '2024-06-26 00:00:00'

/*
Query the event data store over the past month to rank the number of events ingested each day.
*/
SELECT date_trunc('day', eventtime), COUNT(*) AS eventCount FROM $EDS_ID WHERE eventTime > '2024-06-03 00:00:00' GROUP BY date_trunc('day', eventtime) ORDER BY count(*) DESC

/*
Find the number of calls per service that used the outdated Transport Layer Security (TLS) versions 1.0 and 1.1 within the past week.
*/

SELECT eventSource, COUNT(*) AS numOutdatedTlsCalls FROM $EDS_ID WHERE tlsDetails.tlsVersion IN ('TLSv1', 'TLSv1.1') AND eventTime > '2024-06-26 00:00:00' GROUP BY eventSource ORDER BY numOutdatedTlsCalls DESC

/*
Find the callers who used outdated Transport Layer Security (TLS) versions 1.0 and 1.1 within the past week grouped by the number of calls per service.
*/

SELECT recipientAccountId, year(eventTime) AS year_date, month(eventTime) AS month_date, eventSource, sourceIPAddress, userAgent, userIdentity.arn, userIdentity.accesskeyid, COUNT(*) AS numCalls FROM $EDS_ID WHERE tlsDetails.tlsVersion IN ('TLSv1', 'TLSv1.1') AND eventTime > '2024-06-26 00:00:00' GROUP BY recipientAccountId, year(eventTime), month(eventTime), eventSource, sourceIPAddress, userAgent, userIdentity.arn, userIdentity.accesskeyid ORDER BY COUNT(*) DESC

/*
Find users with write permissions who made changes using the console within the past week.
*/

SELECT userIdentity.arn AS user, eventName, eventTime, awsRegion, requestParameters AS resourceChangedManually FROM $EDS_ID WHERE sessionCredentialFromConsole='true' AND errorCode IS NULL AND eventTime > '2024-06-26 00:00:00'

/*
Find users who logged into the running container and ran commands within the past week.
*/

SELECT userIdentity.arn AS user, element_at(requestParameters, 'container') AS container, element_at(requestParameters, 'command') AS command, eventTime FROM $EDS_ID WHERE eventSource='ecs.amazon.com' AND eventName='ExecuteCommand' AND eventTime > '2024-06-26 00:00:00'

/*
Find security group changes made within the past week.
*/

SELECT eventName, userIdentity.arn AS user, sourceIPAddress, eventTime, element_at(requestParameters, 'groupId') AS securityGroup, element_at(requestParameters, 'ipPermissions') AS ipPermissions FROM $EDS_ID WHERE (element_at(requestParameters, 'groupId') LIKE '%sg-%') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime ASC

/*
Find all security group and network ACL changes within the past week.
*/

SELECT * FROM $EDS_ID WHERE ((eventName LIKE '%SecurityGroup%' OR eventName LIKE '%NetworkAcl%') AND eventName NOT LIKE 'Describe%') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime ASC

/*
Find all service limits increased across different regions and accounts within the past week.
*/

SELECT userIdentity.arn AS user, awsRegion, element_at(serviceEventDetails, 'serviceName') AS ServiceName, element_at(serviceEventDetails, 'quotaName') AS QuotaName, element_at(serviceEventDetails, 'createTime') AS RequestedOn, element_at(serviceEventDetails, 'newQuotaValue') AS NewLimitValue, element_at(serviceEventDetails, 'newStatus') AS Status FROM $EDS_ID WHERE eventSource='servicequotas.amazonaws.com' AND eventName in ('UpdateServiceQuotaIncreaseRequestStatus', 'RequestServiceQuotaIncrease') AND element_at(serviceEventDetails, 'serviceName') != '' AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime ASC

/*
Find all manually created resources within the past week.
*/

SELECT userIdentity.arn AS user, userIdentity, eventTime, eventSource, eventName, awsRegion, requestParameters, resources, requestID, eventID FROM $EDS_ID WHERE (eventName LIKE '%Create%') AND resources IS NOT NULL AND userIdentity.sessioncontext.sessionissuer.username NOT LIKE 'AWSServiceRole%' AND userIdentity.sessioncontext.sessionissuer.username IS NOT NULL AND sourceIpAddress != 'cloudformation.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find all users who accessed a given database and table within the past week and show whether access was successful as configured in LakeFormation.
*/

SELECT eventSource, eventName, userIdentity.arn AS user, element_at(requestParameters, 'databaseName') AS DatabaseName, element_at(requestParameters, 'name') AS TableName, json_array_contains(json_parse(element_at(additionalEventData, 'insufficientLakeFormationPermissions')),'<DatabaseName>:<Table Name>') AS FailedAccess, eventTime FROM $EDS_ID WHERE eventSource ='glue.amazonaws.com' AND element_at(requestParameters, 'databaseName') = '<Database Name>' AND element_at(requestParameters, 'name') = '<Table Name>' AND element_at(additionalEventData, 'lakeFormationPrincipal') != '<ARN of Data Lake Admin Role>' AND eventTime > '2024-06-26 00:00:00'

/*
Find all Glue databases and tables viewed or modified by a given database administrator within the past week.
*/

SELECT element_at(requestParameters, 'databaseName') AS DatabaseName, element_at(requestParameters, 'name') AS TableName, eventName, userIdentity.arn AS user FROM $EDS_ID WHERE eventSource ='glue.amazonaws.com' AND element_at(requestParameters, 'databaseName') IS NOT NULL AND element_at(requestParameters, 'name') IS NOT NULL AND element_at(additionalEventData, 'lakeFormationPrincipal') != '<ARN of Data Lake Admin>' AND eventTime > '2024-06-26 00:00:00' 

/*
Find all active S3 objects for the past week.
*/

SELECT accountid, eventName, eventTime, replace(resourceArn, 'arn:aws:s3:::') as s3Resource, useragent FROM $EDS_ID t CROSS JOIN UNNEST(t.resources) unnested (accountid, resourceType, resourceArn, resourceArnPrefix) WHERE eventSource='s3.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' 

/*
Find the records of all API activities performed with the matching accessKeyId.
*/

SELECT eventTime, eventName, userIdentity.principalId FROM $EDS_ID WHERE userIdentity.accessKeyId LIKE '<accessKeyId>' AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find all unsuccessful console sign-in attempts.
*/

SELECT sourceipaddress, useridentity.arn, errorMessage, additionaleventdata FROM $EDS_ID WHERE eventname = 'ConsoleLogin' AND errorMessage IS NOT NULL AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find all API events that failed due to missing permissions.
*/

SELECT count (*) as TotalEvents, eventsource, eventname, useridentity.arn, errorCode, errorMessage FROM $EDS_ID WHERE (errorcode like '%Denied%' or errorcode like '%Unauthorized%') AND eventTime > '2024-06-26 00:00:00' GROUP BY eventsource, eventname, errorCode, errorMessage, useridentity.arn ORDER BY eventsource, eventname

/*
Find the events that increased your CloudTrail bill.
*/
SELECT eventName, count(eventName) AS apiCallCount, eventSource FROM $EDS_ID WHERE eventTime > '2024-06-03 00:00:00' GROUP BY eventName, eventSource ORDER BY apiCallCount DESC 

/*
Find all PutObject requests sorted by bytesTransferredIn in descending order.
*/

SELECT element_at(requestParameters, 'bucketName') AS s3BucketName, cast(element_at(additionalEventData, 'bytesTransferredIn') AS int) AS bytesTransferredIn FROM $EDS_ID WHERE eventName='PutObject' AND eventTime > '2024-06-26 00:00:00' ORDER BY bytesTransferredIn DESC 

/*
Find all events across multiple event data stores using UNION ALL.
*/

SELECT eventsource, eventname, eventtime FROM $EDS_ID WHERE eventTime > date_add('day', -QUERY_TIME_RANGE_IN_DAYS.WEEKLY, now()) UNION ALL SELECT eventData.eventsource, eventData.eventname, eventData.eventtime FROM $INTEGRATION_EDS_ID WHERE eventData.eventtime > date_add('day', -QUERY_TIME_RANGE_IN_DAYS.WEEKLY, now())

/*
Find all the buckets that haven't been accessed for more than a year.
*/

SELECT element_at(requestParameters, 'bucketName') AS bucketName, max(eventtime) AS lastActivityTime FROM $EDS_ID WHERE eventSource='s3.amazonaws.com' AND element_at(requestParameters, 'bucketName') IS NOT NULL GROUP BY 1 HAVING max(eventTime) < date_add('day', -365, now()) 

/*
Find all EC2 events for the past 3 days.
*/

SELECT eventName, eventTime, element_at(requestParameters, 'name') AS TableName, userIdentity.principalId FROM $EDS_ID WHERE eventSource='ec2.amazonaws.com' AND eventTime > date_add('day', -3, now())

/*
Find the catalog name for all Athena StartQuery requests
*/

SELECT eventTime, json_extract(element_at(requestParameters, 'queryExecutionContext'), '$.catalog') as catalog FROM $EDS_ID WHERE eventSource='athena.amazonaws.com' AND eventName='StartQueryExecution' AND eventTime > '2024-06-26 00:00:00'

/*
Find all S3 requests that accessed the AWSLogs prefix of S3Buckets.
*/

SELECT element_at(requestParameters, 'bucketName') as s3BucketName, eventName, useridentity.arn FROM $EDS_ID WHERE regexp_like(element_at(requestParameters, 'key'), 'AWSLogs') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'bucketName'), eventName, useridentity.arn

/*
Find the usage of all events by part of the globe.
*/

SELECT substr(awsRegion, 1, 2) AS globalCode, count(*) AS totalNumberOfEvents FROM $EDS_ID WHERE eventTime > '2024-06-26 00:00:00' GROUP BY 1 ORDER BY totalNumberOfEvents DESC 

/*
List all the IAM roles assumed to access services.
*/

SELECT eventSource, array_agg(distinct userIdentity.arn) as AssumedRoles FROM $EDS_ID WHERE userIdentity.arn IS NOT NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY eventSource

/*
Find all actions in IAM policies.
*/

SELECT flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar)))) as actions FROM $EDS_ID WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'sts%' OR eventSource like 'iam%') AND eventTime > '2024-06-26 00:00:00'

/*
Find the users who made the most failed API calls within the past week.
*/

SELECT userIdentity.arn as user, COUNT(*) AS error_count FROM $EDS_ID WHERE errorCode IS NOT NULL AND userIdentity.arn IS NOT NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn ORDER BY error_count DESC LIMIT 10

/*
Find the IAM actions used in the most created IAM policies.
*/

SELECT action, count(*) as iamActionUsageCount FROM $EDS_ID CROSS JOIN UNNEST(flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar))))) as t (action) WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'iam%') AND eventName = 'CreatePolicy' AND eventTime > '2024-06-26 00:00:00' GROUP BY action ORDER BY iamActionUsageCount DESC

/*
Find the AWS services used in the most created IAM policies.
*/

SELECT element_at(split(action, ':'), 1) as awsService, count(*) as numberOfServiceActions FROM $EDS_ID CROSS JOIN UNNEST(flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar))))) as t (action) WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'iam%') AND eventName = 'CreatePolicy' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(split(action, ':'), 1) ORDER BY count(*) DESC

/*
Find the least recently used IAM roles.
*/

SELECT coalesce(element_at(requestParameters, 'roleName'), element_at(requestParameters, 'roleArn')) as roleName, max(eventTime) as lastUsage FROM $EDS_ID WHERE eventSource in ('sts.amazonaws.com', 'iam.amazonaws.com') AND eventTime > '2024-06-26 00:00:00' GROUP BY coalesce(element_at(requestParameters, 'roleName'), element_at(requestParameters, 'roleArn')) ORDER BY lastUsage ASC

/*
Find the least recently assumed IAM roles.
*/

SELECT element_at(requestParameters, 'roleArn') as roleArn, max(eventTime) as lastUsage FROM $EDS_ID WHERE eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'roleArn') ORDER BY lastUsage ASC

/*
Find the most frequently assumed IAM roles.
*/
SELECT element_at(requestParameters, 'roleArn') as roleArn, count(*) as timesAssumed FROM $EDS_ID WHERE eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'roleArn') ORDER BY timesAssumed DESC

/*
Find principal IDs whose AssumeRole calls failed.
*/

SELECT userIdentity.arn as callerRole, element_at(split(errorMessage, 'not authorized to perform: sts:AssumeRole on resource: '), 2) as failedToAssume FROM $EDS_ID WHERE eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole' AND errorCode = 'AccessDenied' AND eventTime > '2024-06-26 00:00:00'

/*
Find the users who have turned off multi-factor authentication.
*/

SELECT userIdentity.arn, userIdentity.userName, userIdentity.accountId, useridentity.principalId FROM $EDS_ID WHERE eventSource = 'iam.amazonaws.com' AND eventName in ('DeactivateMFADevice', 'DeleteVirtualMFADevice') AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn, userIdentity.userName, userIdentity.accountId, useridentity.principalId

/*
Find the users who haven't changed their passwords recently.
*/

SELECT userIdentity.arn, userIdentity.userName, userIdentity.accountId, max(eventTime) as lastPasswordChange FROM $EDS_ID WHERE eventName = 'ChangePassword' AND errorCode is NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn, userIdentity.userName, userIdentity.accountId ORDER BY lastPasswordChange ASC

/*
Find all IAM user and role deletions in the past week.
*/

SELECT eventtime AS deletion_time, useridentity.username AS deleted_identity, useridentity.type AS identity_type FROM $EDS_ID WHERE (eventname = 'DeleteUser' AND useridentity.type = 'IAMUser') OR (eventname = 'DeleteRole' AND useridentity.type = 'Role') AND eventTime > '2024-06-26 00:00:00'

/*
Find assume role calls within the same account.
*/

SELECT * FROM $EDS_ID WHERE eventName = 'AssumeRole' AND element_at(split(element_at(requestParameters, 'roleArn'), ':'), 5) = element_at(split(useridentity.arn, ':'), 5) AND eventTime > '2024-06-26 00:00:00'

/*
Find accounts making assume role calls.
*/

SELECT useridentity.accountId, count(*) as numberOfAssumeRoleCalls FROM $EDS_ID WHERE eventName = 'AssumeRole' AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.accountId ORDER BY numberOfAssumeRoleCalls DESC

/*
Identify when IAM access keys were created, who created them on a particular day.
*/

SELECT * FROM $EDS_ID WHERE eventName = 'CreateAccessKey' AND eventTime > '2024-06-26 00:00:00'

/*
Find users who created access keys.
*/

SELECT userIdentity.arn, userIdentity.userName, userIdentity.accountId, count(*) as accessKeyCreationCalls FROM $EDS_ID WHERE eventName = 'CreateAccessKey' AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn, userIdentity.userName, userIdentity.accountId ORDER BY accessKeyCreationCalls DESC

/*
Find IAM changes that modify access to actions that can be used for privilege escalation.
*/

SELECT events.* FROM $EDS_ID as events CROSS JOIN UNNEST(flatten(cast(transform(cast(json_extract(element_at(requestParameters, 'policyDocument'), '$.Statement[*].Action') as array(json)), x -> if(not try(is_json_scalar(x)), x, cast(array[cast(x as varchar)] as json))) as array(array(varchar))))) as t (action) WHERE element_at(requestParameters, 'policyDocument') is not null AND (eventSource like 'sts%' OR eventSource like 'iam%') AND action IN ('iam:AddRoleToInstanceProfile', 'iam:AddUserToGroup', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy', 'iam:AttachUserPolicy', 'iam:CreateAccessKey', 'iam:CreatePolicyVersion', 'iam:CreateRole', 'iam:DeleteRolePolicy', 'iam:DeleteUserPolicy', 'iam:DetachGroupPolicy', 'iam:DetachRolePolicy', 'iam:DetachUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy', 'iam:PutUserPolicy', 'iam:RemoveUserFromGroup', 'iam:SetDefaultPolicyVersion', 'iam:UpdateUser', 'sts:AssumeRole') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find API actions matching an IAM action-level statement.
*/

SELECT eventId, useridentity FROM $EDS_ID CROSS JOIN (VALUES '{"Sid": "Statement1","Effect": "Allow","Action": ["service1:ApiName","service2:*"],"Resource": "*"}') as iam (stmt) WHERE (contains(cast(json_extract(stmt, '$.Action') as array(varchar)), concat(element_at(split(eventsource, '.'), 1), ':', eventName)) OR contains(cast(json_extract(stmt, '$.Action') as array(varchar)), concat(element_at(split(eventsource, '.'), 1), ':*'))) AND cast(json_extract(stmt, '$.Effect') as varchar) = 'Allow' AND eventTime > '2024-06-26 00:00:00'

/*
Find AWS console sign-in events without multi-factor authentication.
*/

SELECT * FROM $EDS_ID WHERE eventName = 'ConsoleLogin' AND cast(useridentity.sessioncontext.attributes.mfaauthenticated as boolean) = false AND eventTime > '2024-06-26 00:00:00'

---------------------------------------------

/* Page 6 to 15 (include) */

/* 
Get most throttled DynamoDB indexes
*/ 
	
SELECT element_at(requestParameters, 'indexName') as indexName, count(*) as throttledCallCount FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND (errorCode like '%Throttling%' OR errorCode like '%Exceeded%') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'indexName') ORDER BY throttledCallCount DESC

/*
Get most throttled DynamoDB indexes by month.
*/

SELECT element_at(requestParameters, 'indexName') as indexName, date_trunc('month', eventTime) as month, count(*) as throttledCallCount FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND (errorCode like '%Throttling%' OR errorCode like '%Exceeded%') AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'indexName'), date_trunc('month', eventTime) ORDER BY month DESC, throttledCallCount DESC

/*
Find DynamoDB tables with most write requests.
*/

SELECT element_at(requestParameters, 'tableName'), count(*) as countOfWrites FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND regexp_like(eventName, '(?i)(Write|Put|agResource|Delete|Update)') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'tableName') ORDER BY countOfWrites DESC

/*
Find DynamoDB tables with most write requests by month.
*/

SELECT element_at(requestParameters, 'tableName'), date_trunc('month', eventTime) as month, count(*) as countOfWrites FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND regexp_like(eventName, '(?i)(Write|Put|agResource|Delete|Update)') AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'tableName'), date_trunc('month', eventTime) ORDER BY month DESC, countOfWrites DESC

/*
Find DynamoDB tables with most read calls.
*/
SELECT resources[1].arn as tableIdentifier, count(*) as readRequestCount FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' and cardinality(resources) > 0 AND regexp_like(eventName, '(?i)(Get|Describe|Query|Scan|ListTags)') AND eventTime > '2024-06-26 00:00:00' GROUP BY resources[1].arn ORDER BY readRequestCount DESC

/*
Find DynamoDB tables with most read requests by month.
*/

SELECT resources[1].arn as tableIdentifier, date_trunc('month', eventTime) as month, count(*) as readRequestCount FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' and cardinality(resources) > 0 AND regexp_like(eventName, '(?i)(Get|Describe|Query|Scan|ListTags)') AND eventTime > '2024-01-05 00:00:00' GROUP BY resources[1].arn, date_trunc('month', eventTime) ORDER BY month DESC, readRequestCount DESC

/*
Find the least recently used DynamoDB tables.
*/

SELECT element_at(requestParameters, 'tableName') as tableIdentifier, max(eventTime) as lastUsage FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' and element_at(requestParameters, 'tableName') is not NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'tableName') ORDER BY lastUsage ASC

/*
Find the age of non-terminated RDS instances.
*/
SELECT element_at(requestParameters, 'dBInstanceIdentifier') as instanceIdentifier, DATE_DIFF('millisecond', eventTime, now()) AS instance_age_ms FROM $EDS_ID WHERE eventsource = 'rds.amazonaws.com' AND eventname like 'Create%' AND element_at(requestParameters, 'dBInstanceIdentifier') != '' AND eventTime > '2024-06-26 00:00:00' AND element_at(requestParameters, 'dBInstanceIdentifier') not in ( SELECT element_at(requestParameters, 'dBInstanceIdentifier') FROM $EDS_ID WHERE eventsource = 'rds.amazonaws.com' AND eventname like 'Delete%' AND eventTime > '2024-06-26 00:00:00' )

/*
Find the most frequently used KMS keys.
*/
SELECT kmsKey.arn, count(*) as keyUsageCount FROM $EDS_ID CROSS JOIN UNNEST(resources) as kmsKey (accountid, type, arn, last) WHERE eventsource='kms.amazonaws.com' AND eventName in ('Decrypt', 'Encrypt', 'GenerateDataKey', 'GenerateDataKeyWithoutPlaintext') AND eventTime > '2024-06-26 00:00:00' GROUP BY kmsKey.arn ORDER BY keyUsageCount DESC

/*
Find the most frequent users of KMS keys.
*/

SELECT distinct kmsKey.arn as keyArn, useridentity.arn as userArn, userAgent, count(*) as keyUsageCount FROM $EDS_ID CROSS JOIN UNNEST(resources) as kmsKey (accountid, type, arn, last) WHERE eventsource='kms.amazonaws.com' AND eventName in ('Decrypt', 'Encrypt', 'GenerateDataKey', 'GenerateDataKeyWithoutPlaintext') AND eventTime > '2024-06-26 00:00:00' GROUP BY kmsKey.arn, useridentity.arn, userAgent ORDER BY keyUsageCount DESC

/*
Find the most frequently used KMS keys by month.
*/
SELECT kmsKey.arn, date_trunc('month', eventTime) as month, count(*) as keyUsageCount FROM $EDS_ID CROSS JOIN UNNEST(resources) as kmsKey (accountid, type, arn, last) WHERE eventsource='kms.amazonaws.com' AND eventName in ('Decrypt', 'Encrypt', 'GenerateDataKey', 'GenerateDataKeyWithoutPlaintext') AND eventTime > '2024-01-05 00:00:00' GROUP BY kmsKey.arn, date_trunc('month', eventTime) ORDER BY month desc, keyUsageCount DESC

/*
Find all the aliases that have been assigned to each KMS key.
*/
SELECT element_at(requestParameters, 'targetKeyId') as keyId, array_agg(distinct element_at(requestParameters, 'aliasName')) as aliases FROM $EDS_ID WHERE eventsource ='kms.amazonaws.com' AND eventName in ('CreateAlias', 'UpdateAlias') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'targetKeyId')

/*
Find the alias most recently assigned to each KMS key.
*/

SELECT element_at(requestParameters, 'targetKeyId') as keyId, max_by(distinct element_at(requestParameters, 'aliasName'), eventTime) as mostRecentAlias FROM $EDS_ID WHERE eventsource = 'kms.amazonaws.com' AND eventName in ('CreateAlias', 'UpdateAlias') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'targetKeyId')

/*
Find the users whose KMS API calls failed due to missing IAM permissions.
*/
SELECT distinct kmsKey.arn as keyArn, useridentity.arn as userArn, userAgent, count(*) as accessDeniedErrorCount FROM $EDS_ID CROSS JOIN UNNEST(resources) as kmsKey (accountid, type, arn, last) WHERE eventsource = 'kms.amazonaws.com' AND errorcode = 'AccessDenied' AND eventTime > '2024-06-26 00:00:00' GROUP BY kmsKey.arn, useridentity.arn, userAgent ORDER BY accessDeniedErrorCount DESC

/*
Find the list of resources subscribed to an SNS topic.
*/

SELECT distinct element_at(subscribed.requestparameters, 'endpoint') as subscribedResources, element_at(subscribed.requestParameters, 'topicArn') as topicArn, element_at(subscribed.responseelements, 'subscriptionArn') as subscriptionArn FROM $EDS_ID as subscribed WHERE subscribed.eventSource = 'sns.amazonaws.com' AND subscribed.eventName = 'Subscribe' AND subscribed.errorCode is NULL AND element_at(subscribed.requestParameters, 'topicArn') = 'arn:aws:sns:us-east-1:123456789012:topicName' AND subscribed.eventTime > '2024-06-26 00:00:00' AND not exists ( SELECT element_at(unsubscribed.requestparameters, 'subscriptionArn') FROM $EDS_ID as unsubscribed WHERE unsubscribed.eventSource = 'sns.amazonaws.com' AND unsubscribed.eventName = 'Unsubscribe' AND unsubscribed.errorCode is NULL AND element_at(subscribed.responseelements, 'subscriptionArn') = element_at(unsubscribed.requestParameters, 'subscriptionArn') AND unsubscribed.eventTime > '2024-06-26 00:00:00' )

/*
Find the count of messages published per SNS topic.
*/
SELECT element_at(requestParameters, 'topicArn') as topicArn, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'successful'))), 1)) as totalNumberOfMessages FROM $EDS_ID as subscribed WHERE eventSource = 'sns.amazonaws.com' AND eventName LIKE 'Publish%' AND errorCode is null AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'topicArn') ORDER BY totalNumberOfMessages DESC

/*
Find the count of messages published per SNS topic per month.
*/
SELECT element_at(requestParameters, 'topicArn') as topicArn, date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'successful'))), 1)) as totalNumberOfMessages FROM $EDS_ID as subscribed WHERE eventSource = 'sns.amazonaws.com' AND eventName LIKE 'Publish%' AND errorCode is null AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) , element_at(requestParameters, 'topicArn') ORDER BY date_trunc('month', eventTime) DESC, totalNumberOfMessages DESC

/*
Find the count of SNS messages published per month.
*/
SELECT date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'successful'))), 1)) as totalNumberOfMessages FROM $EDS_ID as subscribed WHERE eventSource = 'sns.amazonaws.com' AND eventName LIKE 'Publish%' AND errorCode is null AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) ORDER BY date_trunc('month', eventTime) DESC

/*
Find the count of throttled SNS messages per topic.
*/
SELECT element_at(requestParameters, 'topicArn') as topicArn, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'failed'))), 1)) as totalNumberOfMessages FROM $EDS_ID as subscribed WHERE eventSource = 'sns.amazonaws.com' AND eventName LIKE 'Publish%' AND errorCode LIKE 'Throttling%' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'topicArn') ORDER BY totalNumberOfMessages DESC

/*
Find the total count of throttled SNS messages per month.
*/
SELECT date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'failed'))), 1)) as totalNumberOfMessages FROM $EDS_ID as subscribed WHERE eventSource = 'sns.amazonaws.com' AND eventName LIKE 'Publish%' AND errorCode LIKE 'Throttling%' AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) ORDER BY date_trunc('month', eventTime) DESC

/*
Find the count of throttled SNS messages per topic on a monthly basis.
*/
SELECT element_at(requestParameters, 'topicArn') as topicArn, date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'failed'))), 1)) as totalNumberOfMessages FROM $EDS_ID as subscribed WHERE eventSource = 'sns.amazonaws.com' AND eventName LIKE 'Publish%' AND errorCode LIKE 'Throttling%' AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) , element_at(requestParameters, 'topicArn') ORDER BY date_trunc('month', eventTime) DESC, totalNumberOfMessages DESC

/*
Find the count of SQS messages sent per queue.
*/
SELECT element_at(requestParameters, 'queueUrl') as queueUrl, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'successful'))), 1)) as totalNumberOfMessages FROM $EDS_ID WHERE eventSource = 'sqs.amazonaws.com' AND eventName LIKE 'SendMessage%' AND errorcode is null AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'queueUrl') ORDER BY totalNumberOfMessages DESC

/*
Find the count of SQS messages sent per queue on a monthly basis.
*/
SELECT element_at(requestParameters, 'queueUrl') as queueUrl, date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'successful'))), 1)) as totalNumberOfMessages FROM $EDS_ID WHERE eventSource = 'sqs.amazonaws.com' AND eventName LIKE 'SendMessage%' AND errorcode is null AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'queueUrl'), date_trunc('month', eventTime) ORDER BY month DESC, totalNumberOfMessages DESC

/*
Find the count of SQS messages sent on a monthly basis.
*/
SELECT date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'successful'))), 1)) as totalNumberOfMessages FROM $EDS_ID WHERE eventSource = 'sqs.amazonaws.com' AND eventName LIKE 'SendMessage%' AND errorcode is null AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) ORDER BY month DESC, totalNumberOfMessages DESC

/*
Find the count of throttled SQS messages per queue.
*/

SELECT element_at(requestParameters, 'queueUrl') as queueUrl, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'failed'))), 1)) as totalNumberOfMessages FROM $EDS_ID WHERE eventSource = 'sqs.amazonaws.com' AND eventName LIKE 'SendMessage%' AND errorcode like 'Throttling%' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'queueUrl') ORDER BY totalNumberOfMessages DESC

/*
Find the throttled SQS message count of queues on a monthly basis.
*/
SELECT element_at(requestParameters, 'queueUrl') as queueUrl, date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'failed'))), 1)) as totalNumberOfMessages FROM $EDS_ID WHERE eventSource = 'sqs.amazonaws.com' AND eventName LIKE 'SendMessage%' AND errorcode like 'Throttling%' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'queueUrl'), date_trunc('month', eventTime) ORDER BY month DESC, totalNumberOfMessages DESC

/*
Find the count of throttled SQS messages per month.
*/
SELECT date_trunc('month', eventTime) as month, sum(coalesce(json_array_length(json_parse(element_at(responseelements, 'failed'))), 1)) as totalNumberOfMessages FROM $EDS_ID WHERE eventSource = 'sqs.amazonaws.com' AND eventName LIKE 'SendMessage%' AND errorcode like 'Throttling%' AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) ORDER BY month DESC, totalNumberOfMessages DESC

/*
Find EventBridge rule disablement and deletion events.
*/
SELECT * FROM $EDS_ID WHERE eventsource = 'events.amazonaws.com' AND eventName in ('DeleteRule', 'DisableRule') AND eventTime > '2024-06-26 00:00:00'

/*
Find distinct KMS key IDs.
*/
SELECT distinct element_at(requestParameters, 'keyId') as kmsKeyId FROM $EDS_ID WHERE eventSource = 'kms.amazonaws.com' AND eventTime > '2024-06-26 00:00:00'

/*
Find the number of readOnly calls made to Glue by different users in a day.
*/
SELECT useridentity.sessioncontext.sessionissuer.arn, COUNT(*) AS countOfReadOnlyCalls FROM $EDS_ID WHERE eventsource = 'glue.amazonaws.com' AND readonly = true AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.sessioncontext.sessionissuer.arn ORDER BY countOfReadOnlyCalls DESC

/*
Find the second of the day that has the most readOnly Glue calls.
*/
SELECT eventtime, COUNT(*) AS countOfReadOnlyCalls FROM $EDS_ID WHERE eventsource = 'glue.amazonaws.com' AND readonly = true AND eventTime > '2024-06-26 00:00:00' GROUP BY eventtime ORDER BY countOfReadOnlyCalls DESC

/*
Check how recently each Lambda function's code was updated.
*/
SELECT element_at(requestParameters, 'functionName') as functionName, max(eventTime) as mostRecentUpdateTime FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'UpdateFunction%' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'functionName') ORDER BY mostRecentUpdateTime

/*
Check the update frequency of each Lambda function.
*/
SELECT element_at(requestParameters, 'functionName') as functionName, count(*) as countOfLambdaUpdates FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'UpdateFunction%' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'functionName') ORDER BY countOfLambdaUpdates DESC

/*
Find the number of times each user updated Lambda functions.
*/
SELECT element_at(requestParameters, 'functionName') as functionName, useridentity.arn, count(*) as countOfLambdaUpdates FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'UpdateFunction%' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'functionName'), useridentity.arn ORDER BY useridentity.arn, element_at(requestParameters, 'functionName'), countOfLambdaUpdates DESC

/*
Find the users with the most Lambda code contributions.
*/
SELECT useridentity.arn, count(*) as countOfLambdaUpdates FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'UpdateFunction%' AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.arn ORDER BY countOfLambdaUpdates DESC

/*
Find the users with the most Lambda code contributions on a monthly basis.
*/
SELECT useridentity.arn, date_trunc('month', eventTime), count(*) as countOfLambdaUpdates FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'UpdateFunction%' AND eventTime > '2024-01-05 00:00:00' GROUP BY useridentity.arn, date_trunc('month', eventTime) ORDER BY date_trunc('month', eventTime) DESC, countOfLambdaUpdates DESC

/*
Find the users who invoked Lambda functions.
*/
SELECT useridentity.arn, count(*) as countOfLambdaInvocations FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'Invoke%' AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.arn ORDER BY countOfLambdaInvocations DESC

/*
Find the users who invoked Lambda functions on a monthly basis.
*/
SELECT useridentity.arn, date_trunc('month', eventTime), count(*) as countOfLambdaInvocations FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'Invoke%' AND eventTime > '2024-01-05 00:00:00' GROUP BY useridentity.arn, date_trunc('month', eventTime) ORDER BY date_trunc('month', eventTime) DESC, countOfLambdaInvocations DESC

/*
Find the number of Lambda invocations.
*/
SELECT element_at(requestParameters, 'functionName') as functionName, count(*) as countOfLambdaInvocations FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'Invoke%' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'functionName') ORDER BY countOfLambdaInvocations DESC

/*
Find the number of Lambda invocations on a monthly basis.
*/
SELECT element_at(requestParameters, 'functionName') as functionName, date_trunc('month', eventtime) as month, count(*) as countOfLambdaInvocations FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'Invoke%' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'functionName'), date_trunc('month', eventtime) ORDER BY month DESC, countOfLambdaInvocations DESC

/*
Find the number of Lambda invocations per user on a monthly basis.
*/
SELECT element_at(requestParameters, 'functionName') as functionName, useridentity.arn, date_trunc('month', eventTime) as month, count(*) as countOfLambdaInvocations FROM $EDS_ID WHERE eventSource = 'lambda.amazonaws.com' AND eventName LIKE 'Invoke%' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'functionName'), date_trunc('month', eventTime), useridentity.arn ORDER BY month DESC, countOfLambdaInvocations DESC

/*
Get list of RDS instances created but not deleted.
*/
SELECT element_at(requestParameters, 'dBInstanceIdentifier') as dBInstanceIdentifier FROM $EDS_ID WHERE eventsource = 'rds.amazonaws.com' AND eventname like 'Create%' AND eventTime > '2024-06-26 00:00:00' EXCEPT SELECT element_at(requestParameters, 'dBInstanceIdentifier') as dBInstanceIdentifier FROM $EDS_ID WHERE eventsource = 'rds.amazonaws.com' AND eventname like 'Delete%' AND eventTime > '2024-06-26 00:00:00'

/*
Get list of RDS clusters created but not deleted.
*/
SELECT element_at(requestParameters, 'dBClusterIdentifier') as clusterIdentifier FROM $EDS_ID WHERE eventsource = 'rds.amazonaws.com' AND eventname like 'Create%' AND element_at(requestParameters, 'dBClusterIdentifier') != '' AND eventTime > '2024-06-26 00:00:00' EXCEPT SELECT element_at(requestParameters, 'dBClusterIdentifier') as clusterIdentifier FROM $EDS_ID WHERE eventsource = 'rds.amazonaws.com' AND eventname like 'Delete%' AND eventTime > '2024-06-26 00:00:00'

/*
Find CloudFormation stack creation and deletion events.
*/
SELECT eventName, eventSource, eventTime, userIdentity.userName FROM $EDS_ID WHERE eventsource = 'cloudformation.amazonaws.com' AND eventName in ('CreateStack', 'DeleteStack') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventtime desc

/*
Find the least recently updated CloudFormation stacks.
*/
SELECT element_at(responseelements, 'stackId') as stackId, max(eventTime) as lastUpdateTime FROM $EDS_ID WHERE eventsource = 'cloudformation.amazonaws.com' AND eventName='UpdateStack' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(responseelements, 'stackId') ORDER BY lastUpdateTime ASC

/*
Find KMS key creation and deletion events.
*/
SELECT * FROM $EDS_ID WHERE eventsource = 'kms.amazonaws.com' AND eventName in ('CreateKey', 'ScheduleKeyDeletion') AND eventTime > '2024-06-26 00:00:00'

/*
Find SNS topic creation events.
*/
SELECT element_at(requestParameters, 'name') as snsTopicName, element_at(requestParameters, 'attributes') as attributes, element_at(responseelements, 'topicArn') as topicArn FROM $EDS_ID WHERE eventSource = 'sns.amazonaws.com' AND eventName = 'CreateTopic' AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find the list of SNS topics that have not been deleted.
*/
SELECT element_at(responseelements, 'topicArn') as arn FROM $EDS_ID WHERE eventSource = 'sns.amazonaws.com' AND eventName = 'CreateTopic' AND eventTime > '2024-06-26 00:00:00' EXCEPT SELECT element_at(requestParameters, 'topicArn') as arn FROM $EDS_ID WHERE eventSource = 'sns.amazonaws.com' AND eventName = 'DeleteTopic' AND eventTime > '2024-06-26 00:00:00'


/*
Find SQS queue creation and deletion events.
*/
SELECT * FROM $EDS_ID WHERE eventName in ('CreateQueue', 'DeleteQueue') AND eventTime > '2024-06-26 00:00:00'

/*
Find the list of ElastiCache serverless cluster modifications.
*/
SELECT json_extract(element_at(responseElements, 'serverlessCache'), 'serverlessCacheName'), eventName, eventSource, eventTime, userIdentity.userName, requestparameters, responseelements FROM $EDS_ID WHERE eventSource = 'elasticache.amazonaws.com' AND eventName IN ('CreateServerlessCache', 'DeleteServerlessCache', 'ModifyServerlessCache') AND eventTime > '2024-06-26 00:00:00' ORDER BY eventTime DESC

/*
Find all gateway configuration changes.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName in ('CreateCustomerGateway', 'DeleteCustomerGateway', 'AttachInternetGateway', 'CreateInternetGateway', 'DeleteInternetGateway', 'DetachInternetGateway') AND eventTime > '2024-06-26 00:00:00'

/*
Get the count of scaling actions per Auto Scaling group.
*/
SELECT element_at(requestParameters, 'autoScalingGroupName') as asgName, count(*) as countOfScalingActions FROM $EDS_ID WHERE eventSource = 'autoscaling.amazonaws.com' AND eventName = 'UpdateAutoScalingGroup' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'autoScalingGroupName') ORDER BY countOfScalingActions DESC

/*
Find the number of scaling actions performed by each Auto Scaling group per month.
*/
SELECT element_at(requestParameters, 'autoScalingGroupName') as asgName, date_trunc('month', eventTime) as month, count(*) as countOfScalingActions FROM $EDS_ID WHERE eventSource = 'autoscaling.amazonaws.com' AND eventName = 'UpdateAutoScalingGroup' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'autoScalingGroupName'), date_trunc('month', eventTime) ORDER BY date_trunc('month', eventTime) DESC, countOfScalingActions DESC

/*
Get the count of scaling actions per month.
*/
SELECT date_trunc('month', eventTime) as month, count(*) as countOfScalingActions FROM $EDS_ID WHERE eventSource = 'autoscaling.amazonaws.com' AND eventName = 'UpdateAutoScalingGroup' AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) ORDER BY date_trunc('month', eventTime) DESC, countOfScalingActions DESC

/*
Find Simple Email Service modification attempts.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'ses.amazonaws.com' AND (eventname in ('VerifyEmailIdentity', 'CreateEmailIdentity', 'DeleteIdentity','DeleteEmailIdentity') OR (eventName = 'UpdateAccountSendingEnabled' AND element_at(requestParameters, 'enabled') is not null) OR (eventName = 'PutAccountSendingAttributes' AND element_at(requestParameters, 'sendingEnabled') is not null)) AND eventTime > '2024-06-26 00:00:00'

/*
Find CloudWatch Logs log group deletion events.
*/
SELECT * FROM $EDS_ID WHERE eventsource = 'cloudwatch.amazonaws.com' AND eventname = 'DeleteLogGroup' AND eventTime > '2024-06-26 00:00:00'

/*
Find CloudWatch rules that are disabled and deleted.
*/
SELECT * FROM $EDS_ID WHERE eventsource = 'cloudwatch.amazonaws.com' AND eventname in ('DisableRule', 'DeleteRule') AND eventTime > '2024-06-26 00:00:00'

/*
Find AWS Detective Graph deletion events.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'detective.amazonaws.com' AND eventName = 'DeleteGraph' AND eventTime > '2024-06-26 00:00:00'

/*
Find ECS cluster deletion events.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'DeleteCluster' AND eventTime > '2024-06-26 00:00:00'

/*
Detect EC2 subnet deletion.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'DeleteSubnet' AND eventTime > '2024-06-26 00:00:00'

/*
Find users who are most frequently signing in without multi-factor authentication.
*/
SELECT useridentity.principalid, useridentity.username, count(*) as numberOfUserLogins FROM $EDS_ID WHERE eventName = 'ConsoleLogin' AND cast(useridentity.sessioncontext.attributes.mfaauthenticated as boolean) = false AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.principalid, useridentity.username ORDER BY numberOfUserLogins DESC

/*
Find the list of IAM policies created.
*/
SELECT json_extract(element_at(responseElements, 'policy'), '$.policyName') as policyName, json_extract(element_at(responseElements, 'policy'), '$.arn') as policyArn FROM $EDS_ID WHERE element_at(requestParameters, 'policyDocument') is not null AND eventName = 'CreatePolicy' AND eventTime > '2024-06-26 00:00:00'

/*
Find the list of roles with an IAM policy attached.
*/
SELECT element_at(requestParameters,'roleName') as roleName FROM $EDS_ID WHERE eventName = 'AttachRolePolicy' AND element_at(requestParameters, 'policyArn') like 'arn:aws:iam::aws:policy/%' AND eventTime > '2024-06-26 00:00:00'

/*
Find the number of EC2 instances that are running per month.
*/
SELECT sum(json_array_length(json_extract(json_parse(element_at(responseElements, 'instancesSet')), '$.items'))) as numberOfRunInstances, date_trunc('month', eventTime) as month FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com'AND eventName = 'RunInstances' AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime) ORDER BY month DESC

/*
Find EC2 instances that are not terminated.
*/
SELECT instances FROM $EDS_ID CROSS JOIN UNNEST(cast(json_extract(json_parse(element_at(responseElements, 'instancesSet')), '$.items[*].instanceId') as array(varchar))) as t (instances) WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'RunInstances' AND eventTime > '2024-06-26 00:00:00' EXCEPT SELECT instances FROM $EDS_ID CROSS JOIN UNNEST(cast(json_extract(json_parse(element_at(responseElements, 'instancesSet')), '$.items[*].instanceId') as array(varchar))) as t (instances) WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'TerminateInstances' AND eventTime > '2024-06-26 00:00:00'

/*
Find the number of EC2 instances created for each instance type on a monthly basis.
*/
SELECT instanceType, date_trunc('month', eventTime) as month, count(*) as countByInstanceType FROM $EDS_ID CROSS JOIN UNNEST(cast(json_extract(json_parse(element_at(responseElements, 'instancesSet')), '$.items[*].instanceType') as array(varchar))) as t (instanceType) WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'RunInstances' AND eventTime > '2024-01-05 00:00:00' GROUP BY instanceType, date_trunc('month', eventTime) ORDER BY month desc, countByInstanceType DESC

/*
Find the number of EC2 instances created for each instance type.
*/
SELECT instanceType, count(*) as countByInstanceType FROM $EDS_ID CROSS JOIN UNNEST(cast(json_extract(json_parse(element_at(responseElements, 'instancesSet')), '$.items[*].instanceType') as array(varchar))) as t (instanceType) WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'RunInstances' AND eventTime > '2024-06-26 00:00:00' GROUP BY instanceType ORDER BY countByInstanceType DESC

/*
Find EC2 security group change events.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName IN ('AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupEgress') AND eventTime > '2024-06-26 00:00:00'

/*
Find the number of running EC2 instances per availability zone.
*/
SELECT availabilityZone, count(*) as countOfInstances FROM $EDS_ID CROSS JOIN unnest(cast(json_extract(element_at(responseelements, 'instancesSet'), '$.items[*].placement.availabilityZone') as array(varchar))) t (availabilityZone) WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'RunInstances' AND eventTime > '2024-06-26 00:00:00' GROUP BY availabilityZone ORDER BY countOfInstances DESC

/*
Find the number of EC2 instances started using each AMI and also find the first and last time the AMI was used.
*/
SELECT amiId, count(*) as CountOfInstances, max(eventTime) as finalTime, min(eventTime) as initialTime FROM $EDS_ID CROSS JOIN unnest(cast(json_extract(element_at(requestParameters, 'instancesSet'), '$.items[*].imageId') as array(varchar))) as t (amiId) WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'RunInstances' AND eventTime > '2024-06-26 00:00:00' GROUP BY amiId ORDER BY finalTime DESC

/*
Find EBS default encryption disablement events.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'DisableEbsEncryptionByDefault' AND eventTime > '2024-06-26 00:00:00'

/*
Monitor API calls to detect when an EBS snapshot is made public.
*/
SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'ModifySnapshotAttribute' AND element_at(requestparameters, 'attributeType') = 'CREATE_VOLUME_PERMISSION' AND element_at(requestparameters, 'createVolumePermission') is not NULL AND json_array_length(json_extract(element_at(requestparameters, 'createVolumePermission'), '$.add.items[?(@.group === "all")]')) > 0 AND eventTime > '2024-06-26 00:00:00'

/*
Check if a possible attacker has created an EBS snapshot from the EBS volume and modified the permissions of the snapshot to allow it to be shared publicly or with another AWS account within a span of 15 minutes.
*/

SELECT createSnapshotDataStore.* FROM $EDS_ID as createSnapshotDataStore JOIN $EDS_ID as modifySnapshotDataStore ON element_at(createSnapshotDataStore.responseelements, 'snapshotId') = element_at(modifySnapshotDataStore.requestparameters, 'snapshotId') WHERE createSnapshotDataStore.eventSource = 'ec2.amazonaws.com' AND modifySnapshotDataStore.eventSource = 'ec2.amazonaws.com' AND createSnapshotDataStore.eventName = 'CreateSnapshot' AND modifySnapshotDataStore.eventName = 'ModifySnapshotAttribute' AND element_at(modifySnapshotDataStore.requestparameters, 'attributeType') = 'CREATE_VOLUME_PERMISSION' AND createSnapshotDataStore.eventTime > '2024-06-26 00:00:00' AND modifySnapshotDataStore.eventTime > '2024-06-26 00:00:00'

/*
Find the age of each S3 bucket.
*/
SELECT element_at(requestParameters, 'bucketName') AS bucket_name, DATE_DIFF('millisecond', eventTime, now()) AS bucket_age_ms FROM $EDS_ID WHERE eventName = 'CreateBucket' AND eventTime > '2024-06-26 00:00:00' ORDER BY bucket_age_ms DESC

/*
Find the users making the most S3 API calls within the past week.
*/
SELECT userIdentity.arn, COUNT(*) AS s3_call_count FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' GROUP BY userIdentity.arn ORDER BY s3_call_count DESC

/*
Find users whose S3 API calls fail frequently due to missing IAM permissions.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, userIdentity.userName, userIdentity.arn, userIdentity.principalId, userIdentity.accountId, count(*) as failedCallCount FROM $EDS_ID WHERE errorCode = 'AccessDenied' AND eventSource = 's3.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'bucketName'), userIdentity.userName, userIdentity.arn, userIdentity.principalId, userIdentity.accountId ORDER BY failedCallCount DESC

/*
Find the most throttled S3 buckets.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, count(*) as failedCallCount FROM $EDS_ID WHERE errorCode IN ('InternalError', 'SlowDown', '503 SlowDown') AND eventSource = 's3.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'bucketName') ORDER BY failedCallCount DESC

/*
Find the most throttled S3 buckets for each month.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, date_trunc('month', eventTime) as month, count(*) as failedCallCount FROM $EDS_ID WHERE errorCode IN ('InternalError', 'SlowDown', '503 SlowDown') AND eventSource = 's3.amazonaws.com' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'bucketName'), date_trunc('month', eventTime) ORDER BY failedCallCount DESC

/*
Find S3 buckets with most write requests.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, count(*) as writeRequestCount FROM $EDS_ID WHERE eventSource='s3.amazonaws.com' AND regexp_like(eventName, '(?i)(Put|agResource|Update|Delete|Create|Upload|Copy)') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'bucketName') ORDER BY writeRequestCount DESC

/*
Find S3 buckets with most write requests by month.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, date_trunc('month', eventTime) as month, count(*) as writeRequestCount FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' AND regexp_like(eventName, '(?i)(Put|agResource|Update|Delete|Create|Upload|Copy)') AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'bucketName'), date_trunc('month', eventTime) ORDER BY month DESC, writeRequestCount DESC

/*
Find S3 buckets with most read requests.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, count(*) as readRequestCount FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' and element_at(requestParameters, 'bucketName') is not NULL AND regexp_like(eventName, '(?i)(Get|Head|List)') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'bucketName') ORDER BY readRequestCount DESC

/*
Find S3 buckets with most read requests by month.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, date_trunc('month', eventTime) as month, count(*) as readRequestCount FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' and element_at(requestParameters, 'bucketName') is not NULL AND regexp_like(eventName, '(?i)(Get|Head|List)') AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'bucketName'), date_trunc('month', eventTime) ORDER BY month DESC, readRequestCount DESC

/*
Find the least recently used S3 buckets.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, max(eventTime) as lastUsage FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' and element_at(requestParameters, 'bucketName') is not NULL AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'bucketName') ORDER BY lastUsage ASC

/*
Find S3 bucket access changes.
*/
SELECT element_at(requestParameters, 'bucketName') as bucketName, eventTime, requestParameters FROM $EDS_ID WHERE eventsource = 's3.amazonaws.com' AND eventName in ('PutBucketAcl', 'DeleteBucketPolicy', 'PutBucketPolicy', 'PutBucketCors','PutBucketLifecycle', 'PutBucketReplication', 'DeleteBucketCors', 'DeleteBucketReplication') AND eventTime > '2024-06-26 00:00:00'

/*
Find ListBuckets calls coming from an EC2 instance profile.
*/
SELECT DISTINCT element_at(split(element_at(split(useridentity.arn, ':'), -1), '/'), -1) as roleSessionName FROM $EDS_ID WHERE eventsource = 's3.amazonaws.com' AND eventName LIKE 'ListBuckets' AND element_at(split(element_at(split(useridentity.arn, ':'), -1), '/'), -1) LIKE 'i-%' AND eventTime > '2024-06-26 00:00:00'

/*
Find ListBuckets calls coming from an EC2 instance profile.
*/
SELECT DISTINCT element_at(split(element_at(split(useridentity.arn, ':'), -1), '/'), -1) as roleSessionName FROM $EDS_ID WHERE eventsource = 's3.amazonaws.com' AND eventName LIKE 'ListBuckets' AND element_at(split(element_at(split(useridentity.arn, ':'), -1), '/'), -1) LIKE 'i-%' AND eventTime > '2024-06-26 00:00:00'

/*
Find ListBuckets calls coming from an EC2 instance profile.
*/
SELECT DISTINCT element_at(split(element_at(split(useridentity.arn, ':'), -1), '/'), -1) as roleSessionName FROM $EDS_ID WHERE eventsource = 's3.amazonaws.com' AND eventName LIKE 'ListBuckets' AND element_at(split(element_at(split(useridentity.arn, ':'), -1), '/'), -1) LIKE 'i-%' AND eventTime > '2024-06-26 00:00:00'

/*
Find S3 public access configuration changes.
*/

SELECT * FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' AND eventName in ('PutPublicAccessBlock', 'DeleteAccountPublicAccessBlock') AND eventTime > '2024-06-26 00:00:00'

/*
SELECT * FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' AND eventName in ('PutPublicAccessBlock', 'DeleteAccountPublicAccessBlock') AND eventTime > '2024-06-26 00:00:00'
*/
SELECT * FROM $EDS_ID WHERE eventName = 'PutBucketLifecycle' AND eventTime < date_trunc('day', current_timestamp) AND eventTime > '2024-06-26 00:00:00' AND json_array_length(json_extract(element_at(requestParameters, 'LifecycleConfiguration'), '$.Rule[?(@.Status === "Enabled")]')) > 0 AND json_array_length(json_extract(element_at(requestParameters, 'LifecycleConfiguration'), '$.Rule[*].Expiration.Days')) > 0

/*
Find S3 log lifecycle expiration policies that are set to less than 90 days.
*/
SELECT * FROM $EDS_ID WHERE eventName = 'PutBucketLifecycle' AND eventTime < date_trunc('day', current_timestamp) AND eventTime > '2024-06-26 00:00:00' AND json_array_length(json_extract(element_at(requestParameters, 'LifecycleConfiguration'), '$.Rule[?(@.Expiration.Days < 90)]')) > 0

/*
Find S3 buckets whose MFA is deleted or versioning is suspended.
*/
SELECT json_extract(element_at(requestParameters, 'VersioningConfiguration'), '$.Status'), requestParameters FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' AND eventTime > '2024-06-26 00:00:00' AND (cast(json_extract(element_at(requestParameters, 'VersioningConfiguration'), '$.Status') as varchar) = 'Suspended' OR cast(json_extract(element_at(requestParameters, 'VersioningConfiguration'), '$.MfaDelete') as varchar) = 'Disabled')

/*
Find the age of each DynamoDB table.
*/
SELECT element_at(requestParameters, 'tableName') as tableName, DATE_DIFF('millisecond', eventTime, now()) AS table_age_ms FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND eventName = 'CreateTable' AND eventTime > '2024-06-26 00:00:00'

/*
Find the usage of DynamoDB table indexes in queries.
*/
SELECT element_at(requestParameters, 'indexName') as indexName, count(*) AS indexUsageCount FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND eventName = 'Query' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'indexName') ORDER BY indexUsageCount DESC

/*
Find the fields used in DynamoDB table scans.
*/
SELECT element_at(requestParameters, 'tableName') as tableName, scanfields, count(*) as field_usage_count FROM $EDS_ID CROSS JOIN UNNEST(map_values(cast(json_parse(element_at(requestParameters, 'expressionAttributeNames')) as map(varchar, varchar)))) as t (scanfields) WHERE eventSource = 'dynamodb.amazonaws.com' AND eventName = 'Scan' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'tableName'), scanfields ORDER BY field_usage_count DESC

/*
Find the fields used in DynamoDB table queries.
*/

SELECT element_at(requestParameters, 'tableName') as tableName, queryfields, count(*) as field_usage_count FROM $EDS_ID CROSS JOIN UNNEST(map_values(cast(json_parse(element_at(requestParameters, 'expressionAttributeNames')) as map(varchar, varchar)))) as t (queryfields) WHERE eventSource = 'dynamodb.amazonaws.com' AND eventName = 'Query' AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'tableName'), queryfields ORDER BY field_usage_count DESC

/*
Find the most frequently used DynamoDB table indexes by month.
*/
SELECT element_at(requestParameters, 'indexName') as indexName, count(*) as indexUsageCount, date_trunc('month', eventTime) as month FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND eventName = 'Query' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'indexName'), date_trunc('month', eventTime) ORDER BY month DESC, indexUsageCount DESC

/*
Find the fields most frequently used in DynamoDB scans by month.
*/

SELECT element_at(requestParameters, 'tableName') as tableName, scanfields, date_trunc('month', eventTime) as month, count(*) as field_usage_count FROM $EDS_ID CROSS JOIN UNNEST(map_values(cast(json_parse(element_at(requestParameters, 'expressionAttributeNames')) as map(varchar,varchar)))) as t (scanfields) WHERE eventSource = 'dynamodb.amazonaws.com'AND eventName = 'Scan' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'tableName'), scanfields, date_trunc('month', eventTime) ORDER BY month DESC, field_usage_count DESC

/*
Find the fields most frequently used in DynamoDB queries by month.
*/
SELECT element_at(requestParameters, 'tableName') as tableName, queryfields, date_trunc('month', eventTime) as month, count(*) as field_usage_count FROM $EDS_ID CROSS JOIN UNNEST(map_values(cast(json_parse(element_at(requestParameters, 'expressionAttributeNames')) as map(varchar, varchar)))) as t (queryfields) WHERE eventSource = 'dynamodb.amazonaws.com' AND eventName = 'Query' AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'tableName'), queryfields, date_trunc('month', eventTime) ORDER BY month DESC, field_usage_count DESC

/*
Get most throttled DynamoDB tables.
*/
SELECT element_at(requestParameters, 'tableName') as tableName, count(*) as throttledCallCount FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND (errorCode like '%Throttling%' OR errorCode like '%Exceeded%') AND eventTime > '2024-06-26 00:00:00' GROUP BY element_at(requestParameters, 'tableName') ORDER BY throttledCallCount DESC

/*
Get most throttled DynamoDB tables by month.
*/
SELECT element_at(requestParameters, 'tableName') as tableName, date_trunc('month', eventTime) as month, count(*) as throttledCallCount FROM $EDS_ID WHERE eventSource = 'dynamodb.amazonaws.com' AND (errorCode like '%Throttling%' OR errorCode like '%Exceeded%') AND eventTime > '2024-01-05 00:00:00' GROUP BY element_at(requestParameters, 'tableName'), date_trunc('month', eventTime) ORDER BY month DESC, throttledCallCount DESC

--------------------------------------------

/* Page 21 to Page 16 (include) */

/*

Top 10 Insights event sources

Find the top 10 event sources that generated the most Insights events within the past month.

*/

SELECT insightEventSource, -- insightEventName, -- Group by event name COUNT(*) AS eventCount FROM $INSIGHTS_EDS_ID WHERE insightState = 'End' AND insightType = 'ApiCallRateInsight' -- AND insightType = 'ApiErrorRateInsight' -- Filter on API error rate insights AND eventTime > '2024-06-03 00:00:00' GROUP BY insightEventSource -- insightEventName -- Group by event name ORDER BY eventCount DESC LIMIT 10

/*

Detect potential AWS Config disablement events

Find potential AWS Config disablement events.

*/

SELECT * FROM $EDS_ID WHERE eventsource = 'config.amazonaws.com' AND eventname in ('StopConfigurationRecorder', 'DeleteDeliveryChannel', 'PutDeliveryChannel', 'PutConfigurationRecorder') AND eventTime > '2024-06-26 00:00:00'

/*

Investigate evidence and its compliance status

Find evidence with any compliance status across all assessments in account, within the past week.

*/

SELECT eventData.evidenceId, eventData.resourceArn, eventData.resourceComplianceCheck FROM $EVIDENCE_EDS_ID WHERE eventTime > '2024-06-26 00:00:00'

/*

Determine non-compliant evidence for a control

Find all non-compliant evidence within the past week for a specific assessment and control.

*/

SELECT * FROM $EVIDENCE_EDS_ID WHERE eventData.assessmentId = '<assessmentId>' AND eventData.resourceComplianceCheck IN ('NON_COMPLIANT','FAILED','WARNING') AND eventData.controlId IN ('<controlId>') AND eventTime > '2024-06-26 00:00:00'

/*

Count evidence by name

Lists the total evidence for an assessment within the past week, grouped by name and ordered by evidence count.

*/

SELECT eventData.eventName as eventName, COUNT(*) as totalEvidence FROM $EVIDENCE_EDS_ID WHERE eventData.assessmentId = '<assessmentId>' AND eventTime > '2024-06-26 00:00:00' GROUP BY eventData.eventName ORDER BY totalEvidence DESC

/*

Explore evidence by data source and service

Find all evidence within the past week for a specific data source and service.

*/

SELECT * FROM $EVIDENCE_EDS_ID WHERE eventData.service IN ('dynamodb') AND eventData.dataSource IN ('AWS API calls') AND eventTime > '2024-06-26 00:00:00'

/*

Explore compliant evidence by data source and control domain

Find compliant evidence for specific control domains, where the evidence comes from a data source that isn't AWS Config.

*/

SELECT * FROM $EVIDENCE_EDS_ID WHERE eventData.resourceComplianceCheck IN ('PASSED','COMPLIANT') AND eventData.controlDomainName IN ('Logging and monitoring','Data security and privacy') AND eventData.dataSource NOT IN ('AWS Config') AND eventTime > '2024-06-26 00:00:00'

/*

Investigate Insights events

Find all CloudTrail management events that generated an Insights event.

*/

SELECT * FROM $EDS_ID AS me INNER JOIN (SELECT awsRegion, recipientAccountId, insightEventSource, insightEventName, MIN(eventTime) AS insight_start, MAX(eventTime) AS insight_end FROM $INSIGHTS_EDS_ID WHERE sharedEventID = '<sharedEventID>' GROUP BY 1, 2, 3, 4) AS ie ON me.awsRegion = ie.awsRegion AND me.recipientAccountId = ie.recipientAccountId AND me.eventSource = ie.insightEventSource AND me.eventName = ie.insightEventName AND me.eventTime >= ie.insight_start AND me.eventTime <= ie.insight_end ORDER BY me.eventTime

/*

Insights events caused by a user

Find all Insights events caused by a particular user within the past month.

*/

SELECT sharedEventID, eventTime, insightType, insightEventSource AS eventSource, insightEventName AS eventName, insightcontext.attributions[1].insightvalue AS user FROM $INSIGHTS_EDS_ID WHERE insightState = 'End' AND insightcontext.attributions[1].insightvalue LIKE '%<username>%' AND eventTime > '2024-06-03 00:00:00' ORDER BY eventTime DESC

/*

Rank the number of Insights events per day

Query the Insights event data store over the past month to rank the number of Insights events generated each day.

*/

SELECT DATE_TRUNC('day', eventTime) AS eventDate, COUNT(*) AS eventCount, DENSE_RANK() OVER(ORDER BY COUNT(*) DESC) AS eventRank FROM $INSIGHTS_EDS_ID WHERE insightState = 'End' AND insightType = 'ApiCallRateInsight' -- AND insightType = 'ApiErrorRateInsight' -- Filter on API error rate insights AND eventTime > '2024-06-03 00:00:00' GROUP BY DATE_TRUNC('day', eventTime) ORDER BY eventRank

/*

Top 10 Insights event errors

Find the top 10 errors that generated the most Insights events within the past month.

*/

SELECT insightErrorCode, COUNT(*) AS eventCount FROM $INSIGHTS_EDS_ID WHERE insightState = 'End' AND insightType = 'ApiCallErrorInsight' AND eventTime > '2024-06-03 00:00:00' GROUP BY insightErrorCode ORDER BY eventCount DESC LIMIT 10

/*

AWS Config resource creation time

Find the resource creation time for all AWS Config configuration items generated on a specific date.

*/

SELECT eventData.configuration, eventData.accountId, eventData.awsRegion, eventData.resourceId, eventData.resourceName, eventData.resourceType, eventData.availabilityZone, eventData.resourceCreationTime FROM $CONFIG_EDS_ID WHERE eventTime > '2024-06-26 00:00:00' AND eventTime < '2024-06-27 00:00:00' ORDER BY eventData.resourceCreationTime DESC limit 10;

/*

List instance ID, AMI ID, and tags

Find the instance ID, Amazon Machine Image (AMI) ID, and tags for the specified instance type and region.

*/

SELECT element_at(eventData.configuration, 'imageId') as imageId, element_at(eventData.configuration, 'instanceId') AS instanceId, eventData.tags AS tags FROM $CONFIG_EDS_ID WHERE eventData.resourceType= 'AWS::EC2::Instance' AND eventData.awsRegion= 'us-east-1' AND eventTime > '2024-07-02 00:00:00'

/*

Total count of AWS Config resources

Find the total count of AWS Config resources grouped by resource type, account ID, and region.

*/

SELECT eventData.resourceType, eventData.awsRegion, eventData.accountId, COUNT (*) AS resourceCount FROM $CONFIG_EDS_ID WHERE eventTime > '2024-07-02 00:00:00' GROUP BY eventData.resourceType, eventData.awsRegion, eventData.accountId

/*

Filter AWS Config resources

Find all AWS Config resources matching the specified resource type and tag value.

*/

SELECT eventData.resourceId, eventData.resourceName, eventData.resourceType, eventData.accountId, eventData.tags AS tags FROM $CONFIG_EDS_ID WHERE eventData.resourceType = 'AWS::S3::Bucket' AND element_at(eventData.tags, '<tag key>')='<tag value>' AND eventTime > '2024-07-02 00:00:00'

/*

List AWS Config resources for a tag key

Find all AWS Config resources matching the specified tag key.

*/

SELECT eventData.resourceId, eventData.resourceName, eventData.resourceType, eventData.accountId, eventData.tags AS tags FROM $CONFIG_EDS_ID WHERE element_at(eventData.tags, '<tag key>')='<tag value>' AND eventTime > '2024-07-02 00:00:00'

/*

Get latest configuration item

Find the latest configuration item for each of your resources.

*/

SELECT eventData FROM ( SELECT eventData, rank() over (partition by eventData.resourceID order by eventData.configurationItemCaptureTime desc) as rnk FROM $CONFIG_EDS_ID ) as configPartition WHERE rnk = 1;

/*

Counts actions and gets the most recent action associated with each of your AWS Config tracked AWS resources

Counts actions and gets the most recent action associated with each of your AWS Config tracked AWS resources.

*/

SELECT eventData.resourceName, eventData.resourceId, count(*) as numAction, max_by(eventName, cloudtrail_events.eventTime) as mostRecentAction FROM $CONFIG_EDS_ID as config_items JOIN (SELECT ct.*, resourceArn FROM $EDS_ID as ct CROSS JOIN unnest(resources) as t (accountId, resourceType, resourceArn, arnPrefix)) as cloudtrail_events ON config_items.eventdata.arn = cloudtrail_events.resourceArn GROUP BY eventData.resourceId, eventData.resourceName ORDER BY numAction DESC

/*

Get resources in AWS Config with most AccessDenied actions

Finds the resources in AWS Config that have the most AccessDenied actions.

*/

SELECT eventData.resourceName, eventData.resourceId, count(*) as numAction, sum(case when errorCode = 'AccessDenied' then 1 else 0 end) as numDeniedActions, max_by(eventName, cloudtrail_events.eventTime) as mostRecentAction FROM $CONFIG_EDS_ID as config_items JOIN (SELECT ct.*, resourceArn FROM $EDS_ID as ct CROSS JOIN unnest(resources) as t (accountId, resourceType, resourceArn, arnPrefix)) as cloudtrail_events ON config_items.eventdata.arn = cloudtrail_events.resourceArn GROUP BY eventData.resourceId, eventData.resourceName ORDER BY numDeniedActions DESC

/*

Get resources in AWS Config with most errored API calls

Find the resources in AWS Config with most errored API calls.

*/

SELECT eventData.resourceName, eventData.resourceId, count(*) as numAction, sum(case when errorCode is not null then 1 else 0 end) as numErroredActions, max_by(eventName, cloudtrail_events.eventTime) as mostRecentAction FROM $CONFIG_EDS_ID as config_items JOIN (SELECT ct.*, resourceArn FROM $EDS_ID as ct CROSS JOIN unnest(resources) as t (accountId, resourceType, resourceArn, arnPrefix)) as cloudtrail_events ON config_items.eventdata.arn = cloudtrail_events.resourceArn GROUP BY eventData.resourceId, eventData.resourceName ORDER BY numErroredActions DESC

/*

Get resources in AWS Config with calls from the most distinct principals

Find the resources in AWS Config with calls from the most distinct principals.

*/

SELECT eventData.resourceName, eventData.resourceId, count(*) as numAction, count(distinct useridentity.principalId) as numDistinctCallers, max_by(eventName, cloudtrail_events.eventTime) as mostRecentAction FROM $CONFIG_EDS_ID as config_items JOIN (SELECT ct.*, resourceArn FROM $EDS_ID as ct CROSS JOIN unnest(resources) as t (accountId, resourceType, resourceArn, arnPrefix)) as cloudtrail_events ON config_items.eventdata.arn = cloudtrail_events.resourceArn GROUP BY eventData.resourceId, eventData.resourceName ORDER BY numDistinctCallers DESC

/*

Track Simple Notification Service enumeration attempts

Find Simple Notification Service enumeration attempts.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'sns.amazonaws.com' AND eventname in ('GetSMSAttributes', 'GetSMSSandboxAccountStatus', 'ListOriginationNumbers', 'ListTopics', 'ListSubscriptions') AND eventTime > '2024-06-26 00:00:00'

/*

Track AWS accounts trying to leave AWS organization

Find AWS accounts trying to leave their organization.

*/

SELECT * FROM $EDS_ID WHERE eventName = 'LeaveOrganization' AND eventTime > '2024-06-26 00:00:00'

/*

Count the number of GetSecretValue calls per user

Find the number of times secret values are accessed by each user.

*/

SELECT useridentity.principalid, useridentity.username, count(*) as numberOfCalls FROM $EDS_ID WHERE eventSource = 'secretsmanager.amazonaws.com' AND eventName = 'GetSecretValue' AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.principalid, useridentity.username ORDER BY numberOfCalls DESC

/*

Count the number of GetSecretValue calls for each user per month

Find the number of times secret values are accessed by each user per month.

*/

SELECT useridentity.principalid, useridentity.username, date_trunc('month', eventTime) as month, count(*) as numberOfCalls FROM $EDS_ID WHERE eventSource = 'secretsmanager.amazonaws.com' AND eventName = 'GetSecretValue' AND eventTime > '2024-01-05 00:00:00' GROUP BY useridentity.principalid, useridentity.username, date_trunc('month', eventTime) ORDER BY date_trunc('month', eventTime) DESC, numberOfCalls DESC

/*

Investigate GuardDuty Detector deletions

Find GuardDuty Detector deletions.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'guardduty.amazonaws.com' AND eventName = 'DeleteDetector' AND eventTime > '2024-06-26 00:00:00'

/*

Investigate AWS GuardDuty publishing destination deletions

Find AWS GuardDuty publishing destination deletions.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'guardduty.amazonaws.com' AND eventName = 'DeletePublishingDestination' AND eventTime > '2024-06-26 00:00:00'

/*

Investigate AWS GuardDuty threat intel set deletions

Find AWS GuardDuty threat intel set deletions.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'guardduty.amazonaws.com' AND eventName = 'DeleteThreatIntelSet' AND eventTime > '2024-06-26 00:00:00'

/*

Identify the user who broke compliance on a DynamoDB table

Find which user performed an action that resulted in a non-compliant status by joining a configuration item event data store with a CloudTrail event data store.

*/

SELECT element_at(config1.eventData.configuration, 'targetResourceId') as targetResourceId, element_at(config1.eventData.configuration, 'complianceType') as complianceType, config2.eventData.resourceType, cloudtrail.userIdentity FROM $CONFIG_EDS_ID as config1 JOIN $CONFIG_EDS_ID as config2 on element_at(config1.eventData.configuration, 'targetResourceId') = config2.eventData.resourceId JOIN $EDS_ID as cloudtrail on config2.eventData.arn = element_at(cloudtrail.resources, 1).arn WHERE element_at(config1.eventData.configuration, 'configRuleList') is not null AND element_at(config1.eventData.configuration, 'complianceType') = 'NON_COMPLIANT' AND cloudtrail.eventTime > '2024-06-26 00:00:00' AND config2.eventData.resourceType = 'AWS::DynamoDB::Table'

/*

Monitor AWS Config rule compliance

Find all AWS Config rules and return the compliance state from configuration items generated within the past day.

*/

SELECT eventData.configuration, eventData.accountId, eventData.awsRegion, eventData.resourceName, eventData.resourceCreationTime, element_at(eventData.configuration, 'complianceType') AS complianceType, element_at(eventData.configuration, 'configRuleList') AS configRuleList, element_at(eventData.configuration, 'resourceId') AS resourceId, element_at(eventData.configuration, 'resourceType') AS resourceType FROM $CONFIG_EDS_ID WHERE eventData.resourceType = 'AWS::Config::ResourceCompliance' AND eventTime > '2024-07-02 00:00:00' ORDER BY eventData.resourceCreationTime DESC limit 10

/*

List AWS Config rules attached to recorded resources

Find all resources recorded by AWS Config within the past week and return the compliance state of all AWS Config rules attached to the resources.

*/

SELECT eventData.configuration, eventData.accountId, eventData.awsRegion, eventData.resourceCreationTime AS resourceCreationTime, element_at(eventData.configuration, 'resourceId') AS resourceId, element_at(eventData.configuration, 'resourceType') AS resourceType, json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[0].configRuleName') AS configRuleName, json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[0].complianceType') AS complianceType FROM $CONFIG_EDS_ID WHERE eventData.resourceType = 'AWS::Config::ResourceCompliance' AND json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[0].complianceType') IS NOT NULL AND eventTime > '2024-06-26 00:00:00' UNION SELECT eventData.configuration, eventData.accountId, eventData.awsRegion, eventData.resourceCreationTime AS resourceCreationTime, element_at(eventData.configuration, 'resourceId') AS resourceId, element_at(eventData.configuration, 'resourceType') AS resourceType, json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[1].configRuleName') AS configRuleName, json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[1].complianceType') AS complianceType FROM $CONFIG_EDS_ID WHERE eventData.resourceType = 'AWS::Config::ResourceCompliance' AND json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[1].complianceType') IS NOT NULL AND eventTime > '2024-06-26 00:00:00' UNION SELECT eventData.configuration, eventData.accountId, eventData.awsRegion, eventData.resourceCreationTime AS resourceCreationTime, element_at(eventData.configuration, 'resourceId') AS resourceId, element_at(eventData.configuration, 'resourceType') AS resourceType, json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[2].configRuleName') AS configRuleName, json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[2].complianceType') AS complianceType FROM $CONFIG_EDS_ID WHERE eventData.resourceType = 'AWS::Config::ResourceCompliance' AND json_extract_scalar(element_at(eventData.configuration, 'configRuleList'),'$[2].complianceType') IS NOT NULL AND eventTime > '2024-06-26 00:00:00' ORDER BY resourceCreationTime DESC;

/* Page 17 */ 

/*

Get most common CloudTrail Lake queries

Find the most frequently run CloudTrail Lake queries.

*/

SELECT COALESCE(element_at(requestParameters, 'queryStatement'), element_at(requestParameters, 'queryAlias') ) as query, count(*) as numberOfExecutions FROM $EDS_ID WHERE eventSource = 'cloudtrail.amazonaws.com' AND eventName='StartQuery' AND eventTime > '2024-06-26 00:00:00' GROUP BY COALESCE(element_at(requestParameters, 'queryStatement'), element_at(requestParameters, 'queryAlias') ) ORDER BY numberOfExecutions DESC

/*

Get most common CloudTrail Lake queries by month

Find the most frequently run CloudTrail Lake queries in each month.

*/

SELECT COALESCE(element_at(requestParameters, 'queryStatement'), element_at(requestParameters, 'queryAlias') ) as query, date_trunc('month', eventTime) as month, count(*) as numberOfExecutions FROM $EDS_ID WHERE eventSource = 'cloudtrail.amazonaws.com' AND eventName='StartQuery' AND eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventTime), COALESCE(element_at(requestParameters, 'queryStatement'), element_at(requestParameters, 'queryAlias') ) ORDER BY month desc, numberOfExecutions DESC

/*

Find most active CloudTrail Lake users

	
Find most active CloudTrail Lake users.

*/

SELECT useridentity.arn, count(*) as queryExecutionCount FROM $EDS_ID WHERE eventsource = 'cloudtrail.amazonaws.com' AND eventName = 'StartQuery' AND eventTime > '2024-06-26 00:00:00' GROUP BY useridentity.arn ORDER BY queryExecutionCount DESC

/*

Get total AWS API usage by month

Find the total AWS API usage on a monthly basis.

*/

SELECT date_trunc('month', eventtime) as month, count(*) as countOfAPIInvocations FROM $EDS_ID WHERE eventTime > '2024-01-05 00:00:00' GROUP BY date_trunc('month', eventtime) ORDER BY date_trunc('month', eventtime) DESC

/*

Get total AWS API usage by time of day

Find the total AWS API usage by the time of day.

*/

SELECT hour(eventtime) as hour, count(*) as countOfAPIInvocations FROM $EDS_ID WHERE eventTime > '2024-06-26 00:00:00' GROUP BY hour(eventtime) ORDER BY hour(eventtime) DESC

/*

Track actions that could disable CloudTrail logging

Find actions that could disable CloudTrail logging.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'cloudtrail.amazonaws.com' AND eventName in ('DeleteEventDataStore', 'DeleteTrail', 'PutEventSelectors', 'PutInsightSelectors', 'StopEventDataStoreIngestion', 'StopLogging', 'UpdateEventDataStore', 'UpdateTrail') AND eventTime > '2024-06-26 00:00:00'

/*

Track AccessDenied events in the past week

Find the number of AccessDenied events in the past week.

*/

SELECT count(*) as numberOfAccessDeniedEvents FROM $EDS_ID WHERE errorCode = 'AccessDenied' AND eventtime >= date_add('day', -7, current_timestamp)

/*

Track AccessDenied events each day

Find the number of AccessDenied events each day.

*/

SELECT date_trunc('day', eventTime) as day, count(*) as numberOfAccessDeniedEvents FROM $EDS_ID WHERE errorCode = 'AccessDenied' AND eventTime > '2024-06-26 00:00:00' GROUP BY date_trunc('day', eventTime) ORDER BY date_trunc('day', eventTime) DESC

/*

Track users making more than 1000 AccessDenied calls in the past week

Find users making more than 1000 AccessDenied calls in the past week.

*/

SELECT userIdentity.userName, userIdentity.arn, userIdentity.principalId, userIdentity.accountId, count(*) as countOfCallsFailedWithAccessDenied FROM $EDS_ID WHERE errorCode = 'AccessDenied' AND eventtime >= date_add('day', -7, current_timestamp) GROUP BY userIdentity.userName, userIdentity.arn, userIdentity.principalId, userIdentity.accountId HAVING count(*) > 1000 ORDER BY countOfCallsFailedWithAccessDenied DESC

/*

Track Simple Email Service enumeration attempts

Find Simple Email Service enumeration attempts.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'ses.amazonaws.com' AND eventname in ('GetAccount', 'GetAccountSendingEnabled', 'ListIdentities', 'ListEmailIdentities','GetSendQuota', 'ListServiceQuotas', 'GetIdentityVerificationAttributes') AND eventTime > '2024-06-26 00:00:00'

/*

Track route table changes

Find changes to route tables.

*/

SELECT coalesce(element_at(requestParameters, 'routeTableId'), cast(json_extract(element_at(responseelements, 'routeTable'), '$.routeTableId') as varchar)) as routeTableId, element_at(requestParameters, 'vpcId') as vpcId, eventTime, requestParameters, responseElements FROM $EDS_ID WHERE eventsource = 'ec2.amazonaws.com' AND eventName in ('CreateRoute', 'ReplaceRoute', 'DeleteRoute', 'CreateRouteTable', 'DeleteRouteTable', 'DisassociateRouteTable', 'ReplaceRouteTableAssociation') AND eventTime > '2024-06-26 00:00:00'

/*

Track route table changes

Find changes to route tables.

*/

SELECT coalesce(element_at(requestParameters, 'routeTableId'), cast(json_extract(element_at(responseelements, 'routeTable'), '$.routeTableId') as varchar)) as routeTableId, element_at(requestParameters, 'vpcId') as vpcId, eventTime, requestParameters, responseElements FROM $EDS_ID WHERE eventsource = 'ec2.amazonaws.com' AND eventName in ('CreateRoute', 'ReplaceRoute', 'DeleteRoute', 'CreateRouteTable', 'DeleteRouteTable', 'DisassociateRouteTable', 'ReplaceRouteTableAssociation') AND eventTime > '2024-06-26 00:00:00'

/*

Track VPC deletion calls

Find VPC deletion calls.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName = 'DeleteVpc' AND eventTime > '2024-06-26 00:00:00'

/*

Track network ACL configuration changes

Find network ACL configuration changes.

*/

SELECT * FROM $EDS_ID WHERE eventSource = 'ec2.amazonaws.com' AND eventName in ('CreateNetworkAcl', 'CreateNetworkAclEntry', 'DeleteNetworkAcl', 'DeleteNetworkAclEntry', 'ReplaceNetworkAclEntry', 'ReplaceNetworkAclAssociation') AND eventTime > '2024-06-26 00:00:00'

/*

List AWS accounts using the services

List all AWS accounts using the services.

*/

SELECT eventSource, array_agg(distinct recipientAccountId) as accounts FROM $EDS_ID WHERE eventTime > '2024-06-26 00:00:00' GROUP BY eventSource

/*

Get the AWS services used by most accounts

Find the AWS services used by most AWS accounts within the past week.

*/

SELECT eventsource as service, COUNT(DISTINCT userIdentity.accountId) AS account_count FROM $EDS_ID WHERE eventName != 'ConsoleLogin' AND eventTime > '2024-06-26 00:00:00' GROUP BY eventsource ORDER BY account_count DESC LIMIT 10

/*

Get the monthly usage for each AWS service

Find the usage of all AWS services on a monthly basis.

*/

SELECT eventSource as service, date_trunc('month', eventTime) as month, COUNT(*) AS service_count FROM $EDS_ID WHERE eventTime > '2024-01-05 00:00:00' GROUP BY eventSource, date_trunc('month', eventTime) ORDER BY month, service_count DESC

/*

Get the monthly usage of AWS services by distinct accounts

Find the monthly usage of AWS services by distinct accounts.

*/

SELECT eventSource as service, date_trunc('month', eventTime) as month, COUNT(DISTINCT userIdentity.accountId) AS account_count FROM $EDS_ID WHERE eventTime > '2024-01-05 00:00:00' GROUP BY eventSource, date_trunc('month', eventTime) ORDER BY month, account_count DESC

/*

Get account level usage of AWS services

Find the number of API calls made to AWS services by accounts.

*/

SELECT eventSource as service, userIdentity.accountId as account_id, COUNT(*) AS service_count FROM $EDS_ID WHERE eventName != 'ConsoleLogin' AND eventTime > '2024-06-26 00:00:00' GROUP BY eventSource, userIdentity.accountId ORDER BY service_count DESC, service

/*

Get account level usage of AWS services per month

Find the number of API calls made to AWS services by accounts each month.

*/

SELECT eventSource as service, userIdentity.accountId as account_id, date_trunc('month', eventTime) as month, COUNT(*) AS service_count FROM $EDS_ID WHERE eventName != 'ConsoleLogin' AND eventTime > '2024-01-05 00:00:00' GROUP BY eventSource, userIdentity.accountId, date_trunc('month', eventTime) ORDER BY month DESC, service_count DESC, service

/* End of Page 21 to 16 (include) */













------------------

/* This query lists Publicly Accessible RDS Instances. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'rds.amazonaws.com'  
    AND eventname = 'CreateDBInstance'  
    AND ELEMENT_AT(requestParameters, 'publiclyAccessible' 
    ) = 'true'SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'rds.amazonaws.com'  
    AND eventname = 'CreateDBInstance'  
    AND ELEMENT_AT(requestParameters, 'publiclyAccessible' 
    ) = 'true'
/* 

This query displays the CloudTrail Lake logs in a flatten table format. This query expands the following objecs: 
userIdentity, userIdentity.sessionContext, userIdentity.sessionContext.attributes, userIdentity.sessionContext.sessionIssuer, 
userIdentity.sessionContext.webidfederationData, and tlsDetails. This query is useful when you are trying to display all 
attributes in an object. This query is helpful to see what colums you can use to pull from the objects available in CloudTrail.

Limitation: This query does not expand Array object. If you are going to attempt to flatten an array, use element_at function.
Eg: element_at(requestParameters, 'ipPermissions')

Note: Add filter Criteria in the where clause to filter the result set. Without a filter criteria, this query will scann all 
the data and will result to very slow query.

*/

SELECT
    eventVersion,
    userIdentity.principalID,
    userIdentity.arn,
    userIdentity.accountID,
    userIdentity.accessKeyID,
    userIdentity.username,
    userIdentity.sessionContext.attributes.creationDate,
    userIdentity.sessionContext.attributes.mfaAuthenticated,
    userIdentity.sessionContext.sessionIssuer.type,
    userIdentity.sessionContext.sessionIssuer.principalID,
    userIdentity.sessionContext.sessionIssuer.arn,
    userIdentity.sessionContext.sessionIssuer.accountID,
    userIdentity.sessionContext.sessionIssuer.username,
    userIdentity.sessionContext.webidfederationData.federatedProvider,
    userIdentity.sessionContext.webidfederationData.attributes,
    userIdentity.sessionContext.sourceIdentity,
    userIdentity.sessionContext.ec2RoleDelivery,
    userIdentity.sessionContext.ec2IssuedInVPC,
    userIdentity.invokedBy,
    userIdentity.identityProvider,
    eventTime,
    eventSource,
    eventName,
    awsRegion,
    sourceIpAddress,
    userAgent,
    errorCode,
    errorMessage,
    requestParameters,
    responseElements,
    additionalEventData,
    requestID,
    eventID,
    readOnly,
    resources,
    eventType,
    apiVersion,
    managementEvent,
    recipientAccountID,
    sharedEventID,
    annotation,
    vpcEndPointID,
    serviceEventDetails,
    addendum,
    edgeDeviceDetails,
    insightDetails,
    eventCategory,
    tlsDetails.tlsVersion,
    tlsDetails.cipherSuite,
    tlsDetails.clientProvidedHostHeader,
    sessionCredentialFromConsole,
    eventJson,
    eventJsonChecksum
FROM
    <event_data_store_id>
WHERE eventTime >= '${date_filter}'
    AND eventTime <= '${date_filter}'
    -- Add filter Criteria in the where clause to filter the result set.
    -- Without a filter criteria, this query will scann all the data and will result to very slow query.
/* This query returns all requests by user by account for the specified time period. Ordered by request count. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.principalid, useridentity.accountId, count(* 
    ) as eventCount 
FROM
    $EDS_ID 
WHERE
    userIdentity.principalid IS NOT NULL  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'
GROUP
    BY userIdentity.principalid, useridentity.accountId ORDER BY EventCount DESC
/* This query returns details when a RDS DB was deleted without taking final snapshot.
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    element_at(requestParameters, 'dBClusterIdentifier' 
    ) as DBCluster, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as DeletedTime
FROM
    $EDS_ID 
WHERE
    eventName = 'DeleteDBCluster'  
    and element_at(requestParameters, 'skipFinalSnapshot' 
    ) = 'true'
/* 
This query returns the PutEvaluation result for Config rules.

Essentially providing the same information returned by the overall resource compliance CI type.
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT
    eventTime,awsRegion, recipientAccountId, element_at(additionalEventData, 'configRuleName'  
    ) as configRuleName, json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceType' 
    ) as Compliance, json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceResourceType' 
    ) as ResourceType, json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceResourceId' 
    ) as ResourceName
FROM
    <event_data_store_id>
WHERE
    eventName='PutEvaluations'  
    AND eventTime > '2023-11-16 00:00:00'  
    AND eventTime < '2023-11-17 00:00:00' 
    And json_extract_scalar(json_array_get(element_at(requestParameters,'evaluations' 
        ),0 
        ),'$.complianceType' 
    ) IN ('COMPLIANT','NON_COMPLIANT'
    ) 
/* This query returns Aurora PostgreSQL databases with Availability zone information.
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    element_at(requestParameters, 'dBInstanceIdentifier'
    ) as DBInstance, element_at(requestParameters, 'engine'
    ) as Engine, element_at(requestParameters, 'engineVersion'
    ) as DBEngineVersion,  element_at(requestParameters, 'availabilityZone'
    ) as AvailabilityZone
FROM
    $EDS_ID 
WHERE
    element_at(requestParameters, 'engine'
    ) = 'aurora-postgresql' 
    and eventname = 'CreateDBInstance' 
    and eventTime >='2021-01-01 00:00:00' 
    and eventTime < '2022-01-01 00:00:00'
/*This query can be used for troubleshooting purposes as it lists all the error messages for S3 source.  You can use the query for all resources, just modifying the eventSource.
Replace <EDS ID> with your Event Data Store Id number.*/

select
    eventType, eventName, errorMessage 
from
    <event_data_store_id> 
where
    errorMessage is not null  
    and eventSource='s3.amazonaws.com'example: select
        eventType, eventName, errorMessage  
    from
        <event_data_store_id>  
    where
        errorMessage is not null  
        and eventSource='s3.amazonaws.com'
/* 
This query returns activity based on mutable APIs and the AWS services performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT eventSource, eventName, eventTime, eventID, errorCode
FROM <EDS ID>
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND readOnly = false
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query confirms who (principal Id) has launched an EC2 instance.
Replace <EDS ID> with your Event Data Store Id number and the <i-b188560f> with the EC2 instance that you are looking for.
*/

SELECT userIdentity.principalid, eventName, eventTime, recipientAccountId, awsRegion 
FROM <EDS ID>
WHERE responseElements IS NOT NULL AND
element_at(responseElements, 'instancesSet') like '%'instanceId':'i-b188560f'%' 
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND eventName='RunInstances'

/* This query lists the count of data events by API actions for a specified S3 bucket
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    eventName, COUNT(*
    ) as requestCount
FROM
    $EDS_ID
WHERE
    eventSource = 's3.amazonaws.com' 
    AND eventCategory = 'Data' 
    AND eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND element_at(requestParameters, 'bucketName'
    ) = 'my-bucket-name'
GROUP
    BY eventNameORDER BY requestCount DESC
/* 
This query returns information about API IAM CreateUserAccessKeys performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventID, eventTime, errorCode, errorMessage
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='CreateAccessKey'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query returns API IAM CreateRole called by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventID, eventTime, errorCode, errorMessage
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='CreateRole'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query returns information about API IAM CreateUser performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventID, eventTime, element_at(responseElements, 'user') as userInfo
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='CreateUser'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query helps to confirm in which AWS accounts the IAM Identify Center user has federated using which IAM roles during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT element_at(serviceEventDetails, 'account_id') as AccountID, element_at(serviceEventDetails, 'role_name') as SSORole, eventID, eventTime
FROM <EDS ID>
WHERE eventSource = 'sso.amazonaws.com'
AND eventName = 'Federate'
AND userIdentity.username = 'alice@example.com'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* This query returns summary of regions in use and well as what services are used in these regions.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    awsRegion, eventSource, COUNT(*  
    ) AS apiCount 
FROM
    $EDS_ID 
WHERE
    eventTime > '2022-04-23 00:00:00'  
    AND eventTime < '2022-11-26 00:00:00' 
GROUP
    BY awsRegion, eventSource ORDER BY apiCount DESC
/* 
This query returns AWS API activity performed by an IAM user access key and from which IP address during specific time window ordered by AWS service.
Replace <EDS ID> with your Event Data Store Id number and <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT eventSource,eventName,sourceIPAddress,eventTime,errorCode
FROM <EDS ID>
WHERE userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
order by eventTime;

/*

This query returns historical changes of security groups. This is useful when you are auditing / investigating
changes made to security groups.

Notice that there are two queries below that are being combined using the 'UNION ALL' clause. 

The first query pulls the AuthorizeSecurityGroupIngress events (for newly created security group rules).
The 2nd query pulls the ModifySecurityGroupRulesRequest (for modification on security group rules).

*/

-- This part of the query returns AuthorizeSecurityGroupIngress events
SELECT
    element_at(requestParameters, 'groupId') AS securityGroup,
    eventName,
    eventTime,
    element_at(requestParameters, 'ipPermissions') AS securityGroupRule,
    userIdentity.arn AS user,
    sourceIPAddress,    
    eventSource
FROM
    <event_data_store_id>
WHERE
    eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-08 00:00:00'
    AND eventName = 'AuthorizeSecurityGroupIngress'     

UNION ALL

-- This part of the query returns ModifySecurityGroupRulesRequest events
SELECT
    json_extract_scalar(element_at(requestParameters, 'ModifySecurityGroupRulesRequest'), '$.GroupId') securityGroup,
    eventName,
    eventTime,
    element_at(requestParameters, 'ModifySecurityGroupRulesRequest') securityGroupRule,
    userIdentity.arn AS user,
    sourceIPAddress,    
    eventSource
FROM
    <event_data_store_id>
WHERE
	eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-09 00:00:00'
	AND eventName = 'ModifySecurityGroupRules'
ORDER BY securityGroup,
    eventTime
/* This query lists raw records for all EC2 management events.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventname IN ('AssociateAddress', 'DisassociateAddress', 'CancelReservedInstancesListing', 'CancelSpotInstanceRequests', 'CreateNetworkAcl', 'DeleteNetworkAcl', 'CreateNetworkAclEntry', '''CreateVpc' , 'DeleteVpcPeeringConnection', 'RevokeSecurityGroupIngress' , 'RevokeSecurityGroupEgress', 'DetachInternetGateway', 'PurchaseReservedInstancesOffering', 'ModifyReservedInstances', 'AcceptVpcPeeringConnection', 'RejectVpcPeeringConnection' , 'CreateVpcPeeringConnection' 
    )
/* This query returns raw records for all 'scan' DunamoDB management events.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'dynamodb.amazonaws.com'  
    AND eventname = 'scan'
/* 

This query returns the historical changes on the public access block policy of s3 buckets. This query is useful when you are 
trying to audit public access block changes or trying to find buckets that are exposed in the internet.

If you are trying to find the current bucket policy that are allowing public access, look at the result set of this query.
Check for the first record of each bucket from the result set. Check each bucket and check if the blockPublicPolicy = false.

*/

SELECT
	element_at(requestParameters, 'bucketName') AS bucketName,
    json_extract_scalar(element_at(requestParameters, 'PublicAccessBlockConfiguration'), '$.RestrictPublicBuckets') AS restrictPublicBuckets,
    json_extract_scalar(element_at(requestParameters, 'PublicAccessBlockConfiguration'), '$.BlockPublicPolicy') AS blockPublicPolicy,
    element_at(requestParameters, 'PublicAccessBlockConfiguration') AS publicAccessBlockConfiguration,
    eventName,
    eventTime,
    requestParameters,
    userIdentity.arn AS user,
    responseElements
FROM
    <event_data_store_id>
WHERE
    eventTime >= '2023-07-07 00:00:00'
    AND eventSource = 's3.amazonaws.com'
    and element_at(requestParameters, 'bucketName') = 'demo-20230707'
    and eventName IN ('PutPublicAccessBlock', 'DeletePublicAccessBlock', 'PutBucketPublicAccessBlock')    
ORDER BY
	bucketName,
    eventTime DESC
    
/* This query returns Aurora MySQL databases with Instance class information created from beginning of 2022. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'dBInstanceIdentifier' 
    ) as DBInstance, element_at(requestParameters, 'dBInstanceClass' 
    ) as InstanceClass, element_at(requestParameters, 'engine' 
    ) as Engine, eventTime as DateTime
FROM
    $EDS_ID 
WHERE
    element_at(requestParameters, 'engine' 
    ) = 'aurora-mysql'  
    and eventname = 'CreateDBInstance'  
    and eventTime >='2022-01-01 00:00:00'
/* This query results are a list in chronological order of DB reboots that have occured
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    element_at(requestParameters, 'dBInstanceIdentifier'  
    ) as DBInstance, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as RebootTime
FROM
    $EDS_ID 
WHERE
    eventName = 'RebootDBInstance'ORDER BY eventTime DESC
/* 
This query count and group activity based on APIs and the AWS services performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT eventSource, eventName, COUNT(*) AS apiCount 
FROM <EDS ID>
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
GROUP BY eventSource, eventName 
ORDER BY apiCount DESC

/* The following query has a filter for EC2 instance where you can replace <instance id> 
in the below query with your own EC2 instance ID to identity patch compliance status for the specific instance. 
The query has a filter for eventTime as well.  You can search patch compliance status based on specific time ranges.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId,eventData.accountId, eventData.awsRegion, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,
  eventTime
    FROM config_event_data_store_ID
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance' 
  AND replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') = '<instance id such as i-123456789012>'
  AND eventTime > '2023-06-23 00:00:00'
  AND eventTime < '2023-06-25 12:00:00'
) where PatchResult is not null;
/* 
This query creates an athena table named awsconfig. 

Use this query to create a table that can be used to get an aggregated count of AWS Config configuration items. 
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id, and replace LOCATION with path to the bucket where your AWS Config snapshot is delivered.
*/

CREATE EXTERNAL TABLE awsconfig (
	fileversion string,
	configSnapshotId string,
	configurationitems ARRAY < STRUCT < configurationItemVersion: STRING,
	configurationItemCaptureTime: STRING,
	configurationStateId: BIGINT,
	awsAccountId: STRING,
	configurationItemStatus: STRING,
	resourceType: STRING,
	resourceId: STRING,
	resourceName: STRING,
	ARN: STRING,
	awsRegion: STRING,
	availabilityZone: STRING,
	configurationStateMd5Hash: STRING,
	resourceCreationTime: STRING > >
)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
LOCATION 's3://config-bucket-PATH';
/* 
This query obtain successful activity performed by IAM user access key during specific window time grouped by AWS services and API.
Replace <EDS ID> with your Event Data Store Id number and the <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT count (*) as NumberEvents, eventSource, eventName
FROM <EDS ID>
WHERE eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
AND errorcode IS NULL
GROUP by eventSource, eventName
order by NumberEvents desc;

/* 
This query obtain S3 bucket and object names affected by an IAM user access kesy during a specifc window time.
Replace <EDS ID> with your Event Data Store Id number and the <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT element_at(requestParameters, 'bucketName') as BucketName, element_at(requestParameters, 'key') as ObjectName, eventName 
FROM <EDS ID>
WHERE (eventName = 'CopyObject' OR eventName = 'DeleteObject' OR eventName = 'DeleteObjects' OR eventName = 'GetObject' OR eventName = 'HeadObject' OR eventName = 'PutObject') 
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'

/* 
This query helps to confirm which IAM role was assumed by an IAM user access keys during specific window time.
Replace <EDS ID> with your Event Data Store Id number and <AKIAIOSFODNN7EXAMPLE> with the IAM user access keys.
*/

SELECT requestParameters,responseElements
FROM <EDS ID>
WHERE eventName = 'AssumeRole'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE';

/* This query can be used if there are requirements to use only a subsets of AWS regions.  
It lists any events which involve non authorized regions which may help to identify non-compliance scenarios. 
Replace <EDS ID> with your Event Data Store Id number and replace <region>, <accountid> with the desired region and your account id.*/




select
    awsRegion, eventType, eventTime, eventName 
from
    <event_data_store_id> 
where
    awsRegion not in ('region','region' 
    )  
    and recipientAccountId='<accountid>': select
        awsRegion, eventType, eventTime, eventName  
    from
        <event_data_store_id>  
    where
        awsRegion not in ('<region>','<region>' 
        )  
        and recipientAccountId='<accountid>'
/* This query identifies the top callers of the AWS IAM service based on their number of API calls. It
   can help you identity which principals are calling IAM the most and if these principals may be close 
   to service limits.
    
    To use this query, Replace <EDS ID> with your Event Data Store Id.
*/


SELECT
	COUNT(*) AS apiCount, eventName, recipientAccountId, userIdentity.principalid
FROM
	<event_data_store_id> 
WHERE
	userIdentity.principalid IS NOT NULL AND eventTime >= '2022-01-08 00:00:00'
    AND
	    eventSource='iam.amazonaws.com'
GROUP BY
	eventName, recipientAccountId, userIdentity.principalid
ORDER BY
	apiCount DESC


/*This query will show if AWS Support has taken over the AWSServiceRoleForSupport Role, for Data Sovereignty requirements.
Replace <EDS ID> with your Event Data Store Id number.*/


select
    eventTime,  eventSource,  eventName,  awsRegion,  sourceIPAddress, userAgent,  userIdentity.type as userIdtype,  element_at(resources, 1
    ).accountId as ressourceAccountID, element_at(resources, 1
    ).arn as ressourceARN, eventType, eventCategory, managementEvent, recipientAccountId, requestParameters, responseElements 
from
    <EDS ID>
where
    eventSource = 'sts.amazonaws.com' 
    and userAgent = 'support.amazonaws.com'

/* 
This query returns EC2 instances information created across the organization during specific window time.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT recipientAccountId, awsRegion, eventID, element_at(responseElements, 'instancesSet') as instances
FROM <EDS ID>
WHERE eventName='RunInstances'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* 
This query confirms if there were any activity performed from IP address in other AWS accounts in your organization except one during specific window time grouped by AWS account.
Replace <EDS ID> with your Event Data Store Id number, the <192.0.2.76> with the IP address you are looking for and the <555555555555> with the AWS account you want to exclude.
*/

SELECT useridentity.accountid 
FROM <EDS ID> 
WHERE sourceIPAddress = '192.0.2.76'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00' 
AND useridentity.accountid != '555555555555' 
GROUP by useridentity.accountid;

/* 
This query returns denied activity based errorCode response and the AWS services performed by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, awsRegion, eventSource, eventName, readOnly, errorCode, errorMessage, eventTime, eventID
FROM <EDS ID>
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND (errorCode = 'AccessDenied' OR errorCode LIKE '%Unauthorized%')
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/*

This query provides events with TLS version and event source. This query is helpful when you are trying to find
specific version of TLS. Eg: If you’re trying to find events realted to TLSv1 (which will have a end of support on June 28. 2023),
You can include in the filter criteria AND CAST(REPLACE(tlsDetails.tlsVersion, 'TLSv', '') AS DOUBLE) <= 1.1

This filters all TLS connections with 1.1 and below. Feel free to change the version number on the filter to tilter out 
different versions. You can also change use different operators such as =, >, <, >=, or <= in filtering TLS versions.

*/

SELECT
    eventSource,
    tlsDetails.tlsVersion,
    sourceIPAddress,
    recipientAccountId,
    COUNT(*) AS numOutdatedTlsCalls
FROM
    <event_data_store_id>
WHERE
    eventTime >= '${date_filter}' -- Eg: '2023-06-20 00:00:00'
    AND eventTime <= '${date_filter}' -- Eg: '2023-06-27 00:00:00'
    AND tlsDetails.tlsVersion LIKE 'TLSv%'
    AND CAST(REPLACE(tlsDetails.tlsVersion, 'TLSv', '') AS DOUBLE) <= 1.1
GROUP BY
    eventSource,
    tlsDetails.tlsVersion,
    sourceIPAddress,
    recipientAccountId
ORDER BY
    numOutdatedTlsCalls DESC

/* This query returns results where cross-account access was granted. 
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    userIdentity.principalid, eventName, eventSource, userIdentity.accountId, recipientAccountId, requestParameters, eventTime
FROM
    $EDS_ID 
WHERE
    eventTime > '2022-04-30 00:00:00'  
    AND eventTime < '2022-06-01 00:00:00'  
    AND userIdentity.accountId != recipientAccountId
/* This query modifications to CloudTrail trails.
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    eventName, element_at(requestParameters,'name' 
    ), userIdentity.principalid, eventTime
FROM
    $EDS_ID 
WHERE
    eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'  
    AND ( eventName = 'CreateTrail'  
        or eventName = 'UpdateTrail'  
        or eventName = 'DeleteTrail'  
        or eventName = 'StartLogging'  
        or eventName = 'StopLogging'  
    )
/* This query returns Aurora Postgresql DB instances that have performance insights enabled
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'dBInstanceIdentifier' 
    ) as DBInstance, element_at(requestParameters, 'engine' 
    ) as Engine, element_at(requestParameters, 'engineVersion' 
    ) as DBEngineVersion
FROM
    $EDS_ID 
WHERE
    element_at(requestParameters, 'engine' 
    ) = 'aurora-postgresql'  
    and eventname = 'CreateDBInstance' 
    and element_at(requestParameters, 'enablePerformanceInsights' 
    ) = 'true'
/* This query analyzes CloudTrail Events and identifies any calls that result in errors.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.arn,eventTime,eventSource,eventName,awsRegion,sourceIPAddress,userAgent,errorCode,errorMessage,requestParameters,readOnly,resources,recipientAccountId,tlsDetails
FROM
    <event-data-store-ID>
WHERE
    errorCode IS NOT NULL  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'
/* 
This query count activity performed by an IAM role during specific time period grouped by AWS services and APIs.
Replace <EDS ID> with your Event Data Store Id number and the <arn:aws:iam::555555555555:role/alice> with the IAM role ARN.
*/

SELECT count (*) as NumberEvents, eventSource, eventName
FROM <EDS ID> 
WHERE eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00' 
AND useridentity.type = 'AssumedRole' 
AND useridentity.sessioncontext.sessionissuer.arn = 'arn:aws:iam::555555555555:role/alice'
GROUP by eventSource, eventName
order by NumberEvents desc;

/*

This query returns ec2 security groups with rules that allow public (0.0.0.0/0) access. This query is useful
when you are trying to audit and investigate security groups allowing public access.

Notice that there are two queries below that are being combined using the 'UNION ALL' clause. 

The first query pulls the AuthorizeSecurityGroupIngress events (for newly created security group rules).
The 2nd query pulls the ModifySecurityGroupRulesRequest (for modification on security group rules).

*/

-- This part of the query returns AuthorizeSecurityGroupIngress events
SELECT
    eventName,
    userIdentity.arn AS user,
    sourceIPAddress,
    eventTime,
    eventSource,
    element_at(requestParameters, 'groupId') AS securityGroup,
    element_at(requestParameters, 'ipPermissions') AS securityGroupRule
FROM
    <event_data_store_id>
WHERE
    eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-08 00:00:00'
    AND eventName = 'AuthorizeSecurityGroupIngress'    
    AND element_at(requestParameters, 'ipPermissions') LIKE '%0.0.0.0/0%' -- this filter is used to find security group changes with public rules.

UNION ALL

-- This part of the query returns ModifySecurityGroupRulesRequest events
SELECT
    eventName,
    userIdentity.arn AS user,
    sourceIPAddress,
    eventTime,
    eventSource,
    json_extract_scalar(element_at(requestParameters, 'ModifySecurityGroupRulesRequest'), '$.GroupId') securityGroup,
    element_at(requestParameters, 'ModifySecurityGroupRulesRequest') securityGroupRule    
FROM
    <event_data_store_id>
WHERE
	eventTime >= '2023-07-06 00:00:00'
    AND eventTime <= '2023-07-09 00:00:00'
	AND eventName = 'ModifySecurityGroupRules'
    AND element_at(requestParameters, 'ModifySecurityGroupRulesRequest') LIKE '%0.0.0.0/0%'  -- this filter is used to find security group changes with public rules.
ORDER
    BY eventTime DESC
/* This query returns snapshots that are created which are not encrypted.  
Replace <EDS ID> with your Event Data Store Id number.
*/


select
    userIdentity.principalid,awsRegion,element_at(requestParameters,'volumeId'  
    ) as volume, json_extract(element_at(requestparameters, 'CreateSnapshotsRequest'  
        ),'$.InstanceSpecification.InstanceId'  
    ) as Instance, element_at(responseElements,'snapshotId'  
    ) as snapshotID 
from
    $EDS_ID
where
    eventName like '%CreateSnapshots%'  
    or eventName like '%CreateSnapshot'  
    and element_at(responseElements,'encrypted'  
    )='false'  
    and eventTime < '2022-01-01 00:00:00'  
    and eventTime > '2022-11-11 00:00:00' 
/* 
This query returns the amount of times an AWS Config rule has been evaluated.

Use this query to Get a total count for the number of times AWS Config rules have been evaluated. 
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT
    count(*
    ) as TotalEvents, date(eventTime
    ) as datestamp,awsRegion, recipientAccountId, element_at(additionalEventData, 'configRuleName'
    ) as configRuleName, element_at(additionalEventData, 'configRuleArn'
    ) as configRuleArn
FROM 
<event_data_store_id>
WHERE
    eventName= 'PutEvaluations'
    and eventTime > '2022-11-01 00:00:00'
    AND eventTime < '2022-11-22 00:00:00'
group
    by date(eventTime
    ), awsRegion, recipientAccountId, additionalEventData
order 
	by date(eventTime
    ) desc, TotalEvents desc, recipientAccountId
/* This query returns tag history for resources.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    awsRegion, eventSource, json_extract_scalar(eventjson, '$.requestParameters.resourcesSet.items[0].resourceId' 
    ) as resourceId, eventTime, eventName, json_extract_scalar(eventjson, '$.requestParameters.tagSet.items[0].key' 
    ) as key, json_extract_scalar(eventjson, '$.requestParameters.tagSet.items[0].value' 
    ) as value, useridentity.arn as identityarn 
from
    $EDS_ID 
where
    eventTime > '2022-01-01 00:00:00'  
    and eventName in ('CreateTags','DeleteTags' 
    )order by resourceId,key,eventTime desc
/* The following query has a filter for EC2 instance where you can replace <instance id> 
in the below query with your own EC2 instance ID to identity patch compliance status for the specific instance.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId,eventData.accountId, eventData.awsRegion, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,
  eventTime
    FROM config_event_data_store_ID 
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance' 
  AND replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') = '<instance id such as i-123456789012>'
) where PatchResult is not null;
/* This query returns the most retrieved S3 Objects.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'bucketName'
    ) as bucketName,  element_at(requestParameters, 'key'
    ) as key,  COUNT(*
    ) as requestCount 
FROM
    $EDS_ID 
WHERE
    eventSource = 's3.amazonaws.com'  
    AND eventCategory = 'Data'  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'  
    AND eventName = 'GetObject' 
GROUP
    BY requestParameters ORDER BY requestCount DESC LIMIT 20;
/* 
This query returns IAM Identity Center users who has authenticated into IAM Identity Center portal during specific window time.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT userIdentity.username, eventTime, recipientAccountId, awsRegion, sourceIPAddress, eventID
FROM FROM <EDS ID>
WHERE eventSource = 'sso.amazonaws.com'
AND eventName = 'Authenticate'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/* This query lists the top Error messages for the specified time range
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    errorCode,  errorMessage,  COUNT(*
    ) as eventCount
FROM
    $EDS_ID
WHERE
    eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND (errorCode is not null 
        or errorMessage is not null
    )
GROUP
    BY errorCode, errorMessageORDER BY eventCount DESCLIMIT 10;
/* This query returns when some user was made admin and who did it (added to any groups with name containing word ‘admin’). Helps identifying privilege escalation related issues.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.principalid, eventName, eventTime, element_at(requestParameters,'userName'  
    ) AS username, element_at(requestParameters,'groupName'  
    ) AS groupname
FROM
    $EDS_ID
WHERE
    eventTime > '2022-04-30 00:00:00'  
    AND eventTime < '2022-11-01 00:00:00'  
    AND eventName = 'AddUserToGroup'  
    AND element_at(requestParameters,'groupName'  
    ) like '%admin%'
/* The below query returns the list of instances without returning duplicate instance IDs. 
The latest EC2 compliance data are returned. By default, CloudTrail Lake query can return 
multiple EC2 instance compliance data because Config keeps track of historical data.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  eventData.accountId, eventData.awsRegion, replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId, eventTime, 
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,eventTime, rank() over (partition by replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') order by eventTime desc) as rnk
    FROM config_event_data_store_ID
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance'
) where rnk = 1
/* This query Shows wich identity is making the most GetObject requests from S3 and what it is downloading, including error detail and attempted unauthorized accesses.
Replace <EDS ID> with your Event Data Store Id number.*/

SELECT
    userIdentity.principalId, errorMessage, element_at(requestParameters, 'bucketName' 
    ) as bucket, element_at(requestParameters, 'key' 
    ) as objectKey, count(* 
    ) as attempts
FROM
    <event_data_store_id> 
WHERE
    eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-30 00:00:00'  
    AND eventSource = 's3.amazonaws.com' 
    AND eventName = 'GetObject'
GROUP
    BY userIdentity.principalId, errorMessage, requestParametersORDER BY attempts desc
/* This query lists the encryption status of Objects uploaded to S3 buckets in the descending order of event time.
Replace <EDS ID> with your Event Data Store Id number.*/

/*Pre-reqs:
Activate data events for S3 and perform upload operations in the S3 bucket which has encryption enabled/disabled and upload object with encryption enabled/disabled. 
*/

select
    recipientAccountId, eventTime, element_at(requestParameters,'bucketName'
    ) AS S3BUCKET , element_at(requestParameters,'key'
    ) AS S3OBJECT, element_at(requestParameters,'x-amz-server-side-encryption'
    ) AS ReqENCRYPTION,element_at(responseElements,'x-amz-server-side-encryption'
    ) AS RespENCRYPTION 
from
    $EDS_ID 
where
    eventName='PutObject' order by eventTime desc
/* This query returns console logins with no MFA. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    *
FROM
    $EDS_ID 
WHERE
    eventsource = 'signin.amazonaws.com'  
    AND eventname = 'ConsoleLogin'  
    AND Element_at(additionaleventdata, 'MFAUsed' 
    ) = 'No'
/* 
This query helps to confirm successful activity performed by IAM role during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the <arn:aws:iam::555555555555:role/alice> with the IAM role ARN.
*/

SELECT eventSource, eventName, eventTime, eventID, errorCode 
FROM <EDS ID> 
WHERE eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'
AND useridentity.type = 'AssumedRole'
AND useridentity.sessioncontext.sessionissuer.arn = 'arn:aws:iam::555555555555:role/alice';

/* This query identifies roles that are assuming themselves.

Roles assuming themselves are typically the result of unnecessary operations in code
Self assume role events count towards the STS quota.
    
    To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/


SELECT
    eventid, eventtime, userIdentity.sessioncontext.sessionissuer.arn as RoleARN, userIdentity.principalId as RoleIdColonRoleSessionName 
from
    <event_data_store_id> 
where
    eventSource = 'sts.amazonaws.com' 
    and eventName = 'AssumeRole' 
    and userIdentity.type = 'AssumedRole' 
    and errorcode IS NULL 
    and userIdentity.sessioncontext.sessionissuer.arn = element_at(resources,1
    ).arn

/* This query returns database failover information: Returns Region, DB, user, and time of a failover event for a database
Replace <EDS ID> with your Event Data Store Id number.
*/


SELECT
    awsRegion as AWSRegion,  element_at(requestParameters, 'dBClusterIdentifier'
    ) as DBCluster, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as FailoverTime
FROM
    $EDS_ID 
WHERE
    eventName = 'FailoverDBCluster'
/* 
This query returns information about API IAM PutRolePolicy called by the IAM Identity Center user during specific window time.
Replace <EDS ID> with your Event Data Store Id number and the IAM Identity Center user <alice@example.com>.
*/

SELECT recipientAccountId, eventID, eventTime, element_at(requestParameters, 'roleName') as roleName, element_at(requestParameters, 'policyDocument') as policyDocument 
FROM $EDS_ID
WHERE userIdentity.principalId LIKE '%alice@example.com'
AND eventName='PutRolePolicy'
AND eventTime > '2023-01-01 00:00:00' AND eventTime < '2023-01-07 00:00:00'

/*This query gets a list of all resources that have been created manually (i.e outside of CloudFormation or via set list of CI/CD users), along with details on the action taken. 
Replace <EDS ID> with your Event Data Store Id number.*/

SELECT
    userIdentity.arn AS user, userIdentity, eventTime, eventSource, eventName, awsRegion, requestParameters, resources, requestID, eventID
FROM
    <EDS ID>
WHERE
    (eventName LIKE '%Create%' 
        OR eventName LIKE '%Update%' 
        OR eventName LIKE '%Put%' 
        OR eventName LIKE '%Delete%'
    )
    AND resources IS NOT NULL
    AND userIdentity.sessioncontext.sessionissuer.username NOT LIKE 'AWSServiceRole%'
    AND userIdentity.sessioncontext.sessionissuer.username NOT IN (''
    )
    AND sourceIpAddress != 'cloudformation.amazonaws.com'ORDER BY eventTime DESC
/* 
This query obtain response element for a given CloudTrail event Id.
Replace <EDS ID> with your Event Data Store Id number and the CloudTrail event Id <3270e016-59a1-4448-8dd1-d27a4796502d>
*/

SELECT responseElements
FROM <EDS ID>
WHERE eventID = '3270e016-59a1-4448-8dd1-d27a4796502d';

/* This query shows counts of all Data events by Day of the Week. 
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    day_of_week(eventTime
    ) as weekday,  COUNT(*
    ) as eventCount
FROM
    $EDS_ID
WHERE
    eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND eventCategory = 'Data'
GROUP
    BY day_of_week(eventTime
    )ORDER BY day_of_week(eventTime
    )
/* The following query run against all EC2 instances to identity patch compliance status. 
The query has a filter for eventTime as well.  You can search patch compliance status based on specific time ranges.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId,eventData.accountId, eventData.awsRegion, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,
  eventTime
    FROM config_event_data_store_ID
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance' 
  AND eventTime > '2023-06-23 00:00:00'
  AND eventTime < '2023-06-25 12:00:00'
) where PatchResult is not null;
/* This query shows all API requests where the specified TLS version was not used.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    eventName,  awsRegion,  sourceIPAddress,  recipientAccountId,  tlsDetails.tlsversion
FROM
    $EDS_ID
WHERE
    eventTime > '2022-01-01 00:00:00' 
    AND eventTime < '2022-01-01 00:00:00' 
    AND tlsDetails.tlsversion != 'TLSv1.3'

/* This query identifies buckets across an Organization with requests that rely on ACLs. This can help when migrating away from legacy ACLs to IAM Policies.

Replace <EDS ID> with your Event Data Store ID number.
*/

SELECT DISTINCT
    element_at(requestParameters, 'bucketName') AS Bucket,
    awsRegion AS Region,
    recipientAccountId AS AccountID
FROM
    <EDS_ID> 
WHERE
    element_at(additionalEventData, 'aclRequired') = 'Yes'
ORDER BY
    recipientAccountId,
    awsRegion
/* 
This query returns the estimated amount of Configuration items per resource type.

Use this query to estimate the cost of the AWS Config recorder.  
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT
    recipientAccountId, awsRegion, eventSource, count(* 
    ) as TotalPossibleCI 
FROM
    <event_data_store_id>
Where
    (eventSource like 'eks%' 
        or eventSource like 'ec2%' 
        or eventSource like 'vpc%'
        or eventSource like 'ecs%' 
        or eventSource like 'iam%' 
        or eventSource like 'autoscaling%' 
        or eventSource like 's3%' 
        or eventSource like 'rds%' 
        or eventSource like 'backup%' 
        or eventSource like 'athena%' 
        or eventSource like 'cloudtrail%' 
        or eventSource like 'cloudfront%' 
        or eventSource like 'cloudformation%' 
        or eventSource like 'code%' 
        or eventSource like 'ecr%' 
        or eventSource like 'lambda%' 
        or eventSource like 'efs%' 
    ) 
    and readOnly=False 
    and managementEvent=True 
    and eventTime > '2023-10-01 00:00:00' 
    AND eventTime < '2023-10-30 00:00:00' 
group
    by recipientAccountId, awsRegion, eventSource Order by recipientAccountId desc, TotalPossibleCI desc
/* This query returns source and target of an RDS point in time restore
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    element_at(requestParameters, 'sourceDBClusterIdentifier' 
    ) as Source, element_at(requestParameters, 'dBClusterIdentifier' 
    ) as Target, userIdentity.sessionContext.sessionIssuer.userName as UserName, eventTime as RestoreTime
FROM
    $EDS_ID 
WHERE
    eventName = 'RestoreDBClusterToPointInTime'
/* The SQL query will be run against the configuration items that been collected from the resource type, 
AWS::SSM::PatchCompliance, as part of the config rule ec2-managedinstance-patch-compliance-status-check.

In the query below, replace config_event_data_store_ID with your own event data store ID.
*/

SELECT
  eventData.accountId, eventData.awsRegion, replace(eventData.resourceId, 'AWS::SSM::ManagedInstanceInventory/') as InstanceId, eventTime,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Installed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Installed,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledOther'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledOther,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'InstalledPendingReboot'), FoundItem -> json_extract(FoundItem, '$.Id')) as InstalledPendingReboot,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Missing'), FoundItem -> json_extract(FoundItem, '$.Id')) as Missing,
  transform(filter(PatchResult, PatchItem -> cast(json_extract(PatchItem, '$.PatchState') as varchar) = 'Failed'), FoundItem -> json_extract(FoundItem, '$.Id')) as Failed
FROM (
    SELECT eventData, map_values(cast(json_extract(json_parse(eventJson), '$.eventData.configuration.AWS:ComplianceItem.Content.Patch') as map(varchar, json))) as PatchResult,eventTime
    FROM config_event_data_store_ID 
    WHERE eventData.resourceType = 'AWS::SSM::PatchCompliance'
) where PatchResult is not null
/* This query analyzes CloudTrail Events and identifies any calls that are made to AWS service APIs via the AWS Management Console.
Replace <EDS ID> with your Event Data Store Id number.
*/

SELECT
    userIdentity.arn,eventTime,eventSource,eventName,awsRegion,sourceIPAddress,userAgent,requestParameters,readOnly,recipientAccountId,sessionCredentialFromConsole
FROM
    <event-data-store-ID>
WHERE
    sessionCredentialFromConsole = true  
    AND readOnly = false  
    AND eventTime > '2022-01-01 00:00:00'  
    AND eventTime < '2022-01-01 00:00:00'
/* 
This query will query the table created by ConfigTableCreation.sql to get an aggregated count of Configuration Items. 

Use this query to understand how many changes have happened on each resource type and resourceID. 
    
To use this query, Replace <event_data_store_id> with your Event Data Store Id.
*/

SELECT configurationItem.resourceType,
	configurationItem.resourceId,
	COUNT(configurationItem.resourceId) AS NumberOfChanges
FROM default.awsconfig
	CROSS JOIN UNNEST(configurationitems) AS t(configurationItem)
WHERE '$path' LIKE '%ConfigHistory%'
	AND configurationItem.configurationItemCaptureTime >= '2023-11-01T%'
	AND configurationItem.configurationItemCaptureTime <= '2023-11-21T%'
GROUP BY configurationItem.resourceType,
	configurationItem.resourceId
ORDER BY NumberOfChanges DESC

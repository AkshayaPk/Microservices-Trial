from __future__ import print_function
from botocore.exceptions import ClientError
import json
import boto3
import logging
import time
import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    #logger.info('Event: ' + str(event))
    #print('Received event: ' + json.dumps(event, indent=2))
    #Initialized Arrays
    #Added more comments
    #HelloHowAreYou
        ids = []
        rdsids = []
        s3ids = []
        ecsids = []
    #FunctionDefinition
        def S3Tag():
            if not detail['requestParameters']:
                logger.warning('Not requestParameters found')
                if detail['errorCode']:
                    logger.error('errorCode: ' + detail['errorCode'])
                if detail['errorMessage']:
                    logger.error('errorMessage: ' + detail['errorMessage'])
                return False 

            if eventname == 'CreateBucket':
                s3ids.append(detail['requestParameters']['bucketName'])
                logger.info(s3ids) 
            else:
                logger.warning('Not supported action')

            if s3ids:
                for s3id in s3ids:
                    print('Tagging resource ' + s3id)
                    bucket_tagging = s3.BucketTagging(s3id)
                    try:
                        tags = bucket_tagging.tag_set
                        tags.append({'Key':'Owner', 'Value': user})
                        tags.append({'Key':'Creator', 'Value': user})
                        tags.append({'Key':'PrincipalId', 'Value': principal})
                        CreateTags = bucket_tagging.put(Tagging={'TagSet':tags})
                    except ClientError:
                        print (s3id+ ",does not have tags, add tag")
                        response = bucket_tagging.put(
                            Tagging={
                                'TagSet': [
                                    {
                                        'Key': 'Owner', 
                                        'Value': user
                                    },
                                    {
                                        'Key': 'PrincipalId', 
                                        'Value': principal
                                    },
                                    {
                                        'Key': 'Creator', 
                                        'Value': user
                                    },
                                ]
                            }
                        ) 
            logger.info(' Remaining time (ms): ' + str(context.get_remaining_time_in_millis()) + '\n')
            return True            

        def EC2Tag():
            if not detail['responseElements']:
                logger.warning('Not responseElements found')
                if detail['errorCode']:
                    logger.error('errorCode: ' + detail['errorCode'])
                if detail['errorMessage']:
                    logger.error('errorMessage: ' + detail['errorMessage'])
                return False

            if eventname == 'CreateVolume':
                ids.append(detail['responseElements']['volumeId'])
                logger.info(ids)

            elif eventname == 'RunInstances':
                items = detail['responseElements']['instancesSet']['items']
                for item in items:
                    ids.append(item['instanceId'])
                logger.info(ids)
                logger.info('number of instances: ' + str(len(ids)))

                base = ec2.instances.filter(InstanceIds=ids)

                #loop through the instances
                for instance in base:
                    for vol in instance.volumes.all():
                        ids.append(vol.id)
                    for eni in instance.network_interfaces:
                        ids.append(eni.id)

            elif eventname == 'CreateImage':
                ids.append(detail['responseElements']['imageId'])
                logger.info(ids)

            elif eventname == 'CreateSnapshot':
                ids.append(detail['responseElements']['snapshotId'])
                logger.info(ids)
            else:
                logger.warning('Not supported action')

            if ids:
                for resourceid in ids:
                    print('Tagging resource ' + resourceid)
                ec2.create_tags(Resources=ids, Tags=[{'Key': 'Owner', 'Value': user}, {'Key': 'PrincipalId', 'Value': principal},{'Key': 'Creator', 'Value': user}])
            logger.info(' Remaining time (ms): ' + str(context.get_remaining_time_in_millis()) + '\n')
            return True


        def RDSTag():
            if not detail['responseElements']:
                logger.warning('Not responseElements found')
                if detail['errorCode']:
                    logger.error('errorCode: ' + detail['errorCode'])
                if detail['errorMessage']:
                    logger.error('errorMessage: ' + detail['errorMessage'])
                return False   
            
            if eventname == 'CreateDBInstance':
                rdsids.append(detail['responseElements']['dBInstanceArn'])
                logger.info(rdsids)
            else:
                logger.warning('Not supported action')        

            
            if rdsids:
                for resourceid in rdsids:
                    print('Tagging resource ' + resourceid)
                rds.add_tags_to_resource(
                ResourceName=resourceid,
                Tags=[
                    {
                        'Key': 'Owner',
                        'Value': user
                    },
                    {
                        'Key': 'PrincipalId',
                        'Value': principal
                    },
                    {
                        'Key': 'Creator',
                        'Value': user
                    },
                ]
            )
            logger.info(' Remaining time (ms): ' + str(context.get_remaining_time_in_millis()) + '\n')
            return True

        def ECSTag():
            if not detail['responseElements']:
                logger.warning('Not responseElements found')
                if detail['errorCode']:
                    logger.error('errorCode: ' + detail['errorCode'])
                if detail['errorMessage']:
                    logger.error('errorMessage: ' + detail['errorMessage'])
                return False 

            if eventname == 'CreateCluster':
                ecsids.append(detail['responseElements']['cluster']['clusterArn'])
                logger.info(ecsids)  

            if eventname == 'CreateService':
                ecsids.append(detail['responseElements']['service']['serviceArn'])
                logger.info(ecsids)  

            if eventname == 'RegisterTaskDefinition':
                ecsids.append(detail['responseElements']['taskDefinition']['taskDefinitionArn'])
                logger.info(ecsids)             

            if ecsids:
                for ecsid in ecsids:
                    print('Tagging resource' + ecsid)
                    response = ecs.tag_resource(
                    resourceArn=ecsid,
                    tags=[
                            {
                            'key': 'Owner',
                            'value': user
                            },
                            {
                            'key': 'PrincipalId',
                            'value': principal
                            },
                            {
                            'key': 'Creator',
                            'value': user
                            },
                    ]
                )     

        try:
            region = event['region']
            detail = event['detail']
            eventname = detail['eventName']
            arn = detail['userIdentity']['arn']
            principal = detail['userIdentity']['principalId']
            userType = detail['userIdentity']['type']

            if userType == 'IAMUser':
                user = detail['userIdentity']['userName']

            else:
                user = principal.split(':')[1]

            ec2 = boto3.resource('ec2')
            rds = boto3.client('rds')
            s3 = boto3.resource('s3')
            s3client = boto3.client('s3')
            ecs = boto3.client('ecs')

            logger.info('principalId: ' + str(principal))
            logger.info('region: ' + str(region))
            logger.info('eventName: ' + str(eventname))
            logger.info('detail: ' + str(detail))
            
            if eventname == 'CreateBucket':
                S3Tag()
            if eventname == 'CreateVolume' or eventname == 'CreateImage' or eventname == 'CreateSnapshot' or eventname=='RunInstances':
                EC2Tag()
            if eventname == 'CreateDBInstance':
                RDSTag()
            if eventname == 'CreateCluster' or eventname == 'CreateService' or eventname == 'RegisterTaskDefinition':
                ECSTag()   
        
        except Exception as e:
                logger.error('Something went wrong: ' + str(e))
                return False    
           
        
            
        
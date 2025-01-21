import boto3
import json
import os
from time import sleep

class CloudtrailLake:


    def __init__(self):
        # Create cloudtrail client
        cloudtrail_client = boto3.client('cloudtrail')
        self.cloudtrail_client = cloudtrail_client
        
    def execRequest(self,sql_query):
        """
        Send the SQL request to cloudtrail lake
        """
        response = self.cloudtrail_client.start_query(
            QueryStatement=sql_query
        )

        query_id = response['QueryId']

        query_status = 'RUNNING'

        while(query_status == 'RUNNING'):
            query_result = self.cloudtrail_client.get_query_results(
                QueryId=query_id
            )
            query_status = query_result['QueryStatus']
            print("Query status: ", query_status)
            #sleep 5s
            sleep(5)

        return query_result
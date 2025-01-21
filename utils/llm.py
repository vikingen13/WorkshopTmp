import boto3
import streamlit as st
import json
import os
from config_file import Config
from datetime import datetime


# Get the current working directory
cwd = os.getcwd()

# Construct the file path
file_path = os.path.join(cwd, 'sql-reference.sql')

# Read the file content
with open(file_path, 'r') as file:
    sql_ref = file.read()
    
class Llm:

    def __init__(self):
        # Create Bedrock client
        bedrock_client = boto3.client(
            'bedrock-runtime',
            # If Bedrock is not activated in us-east-1 in your account, set this value
            # accordingly
            region_name='us-east-1',
        )
        self.bedrock_client = bedrock_client

    def invoke_sql(self, input_text, invalid_queries=[]):
        """
        Make a call to the foundation model through Bedrock
        """

        invalid_queries_prompt = ""
        if invalid_queries:
            for query in invalid_queries:
                invalid_queries_prompt += f"<invalidquery> {query} </invalidquery>"

        # Prepare a Bedrock API call to invoke a foundation model
        prompt = f"""\n\nHuman:
                    <currentdate>{str(datetime.today())}</currentdate>
                    <exemplequeries> {sql_ref} </exemplequeries>
                    {invalid_queries_prompt}
                    based on the example queries, generate a sql request for cloudtrail lake to answer the following question: {input_text}. The event data store ID is {Config.EVENT_DATA_STORE_ID}. Replace the field $EDS_ID by the event data store id in the request.\
                    provide only the sql query ready to be executed and no other comment or explanation. Double check that you replace the field $EDS_ID. If you need to find a user name, use preferably the userIdentity.principalId field.
                    Before you give me the SQL Request I want you to make sure that is a valid Request and change the Request if it's not valid.
                    Make sure is a SQL query following the best practices.
                    information between <invalidquery> are requests that you already proposed and that are containing errors so do not propose them again.
                    Current errors are around date manipulation.
                    \n\nAssistant:"""

        print(prompt)

        model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
        body = {
            "prompt": prompt,
            "max_tokens_to_sample": 4096,
            "temperature": 0.,
        }
        body = json.dumps(body)
        accept = 'application/json'
        contentType = 'application/json'

        # Make the API call to Bedrock
        response = self.bedrock_client.invoke_model(
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": body
                            }
                        ]
                    }
                ]
            }), modelId=model_id, accept=accept, contentType=contentType
        )

        return response

    def generate_answer(self, input_text,query_result):
        """
        Generate an answer from the foundation model
        """

        # Prepare a Bedrock API call to invoke a foundation model
        prompt = f"""\n\nHuman: 
                    <queryresult> {query_result} </queryresult>
                    based on the query result on cloudtrail event data store, answer the following question: {input_text}
                    \n\nAssistant:"""

        print(prompt)

        model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
        body = {
            "prompt": prompt,
            "max_tokens_to_sample": 4096,
            "temperature": 0.,
        }
        body = json.dumps(body)
        accept = 'application/json'
        contentType = 'application/json'

        # Make the API call to Bedrock
        response = self.bedrock_client.invoke_model_with_response_stream(
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": body
                            }
                        ]
                    }
                ]
            }), modelId=model_id, accept=accept, contentType=contentType
        )

        full_response = ""
        response_container = st.empty()
        for event in response['body']:
            if 'chunk' in event:
                chunk = json.loads(event['chunk'].get('bytes').decode('utf-8'))
                if 'delta' in chunk and 'text' in chunk['delta']:
                    text_chunk = chunk['delta']['text']
                    full_response += text_chunk
                    response_container.markdown(full_response + "▌")


        response_container.markdown(full_response)
        return full_response

    def graphData(self, input_text,query_result):
        """
        Create a graph based on the query result
        """
#                        "axe_x": <name of the column x>,
        #                "axe_y": <name of the column y>,
        #                    You shall find a short name for the column x of the graph in the answer.
          #          You shall find a short name for the column y of the graph in the answer.
        # Prepare a Bedrock API call to invoke a foundation model
        #                    The bar graph need to have only 1 column.
    #1            I don't want the query result showing a list of lists, I want to show only a List.
        prompt = f"""\n\nHuman: 
                    <queryresult> {query_result} </queryresult>
                    based on the query result on cloudtrail event data store, and the following question: {input_text};
                    I want to display a bar graph using streamlit and panda.
                    I don't want the query result showing a list of lists, I want to show only a List.
                    I will use the code
                    df = pd.DataFrame(data)
                    st.bar_chart(df)
                    Provide a json containing a panda dataframe ready to use to create the bar graph.
                    I want my bar graph very beautiful and simple to understand, I insist on the simple to understand.
                    From the graph I need to understand quickly the answer of the question I have asked you.
                    You shall decide if a graph is suitable to help to answer the question by saying true or false in the answer.
                    The format of the json shall be the following:
                    {{
                        "graphsuitable": <true or false>,
                        "dataframe": "<panda data in json format>"                    }}
                    \n\nAssistant:"""

        print(prompt)

        model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
        body = {
            "prompt": prompt,
            "max_tokens_to_sample": 4096,
            "temperature": 0.,
        }
        body = json.dumps(body)
        accept = 'application/json'
        contentType = 'application/json'

        # Make the API call to Bedrock
        response = self.bedrock_client.invoke_model(
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": body
                            }
                        ]
                    }
                ]
            }), modelId=model_id, accept=accept, contentType=contentType
        )

        return response

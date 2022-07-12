from google.cloud import bigquery
import pandas as pd
import pandas_gbq
from pandasql import sqldf
import hashlib

bqclient = bigquery.Client()
def analyze(contracts_df, signatures_df, callers_df):
    '''
    Tag known bots. Acts as a 'seed' for the heuristic
    '''
    known_bots_query = """
        select
            *
        from signatures_df
        order by invocations desc
        limit 2
    """

    known_bots_df = sqldf(known_bots_query)

    '''
    All signatures that belong to a smart contract that was classified as bot 
    confidence = 1
    '''
    bot_signature_query = """
        select distinct
            from_address_hash,
            to_address_hash,
            signature,
            invocations,
            'bot' as tag,
            '1' as confidence_level
        from signatures_df 
        where to_address_hash in {}
    """.format(tuple(known_bots_df['to_address_hash'].to_list()))

    bot_signature_df = sqldf(bot_signature_query)
    bot_signature_df['confidence_level'] = bot_signature_df['confidence_level']\
                                                                    .astype(float)
    bot_signature_df['tags'] = bot_signature_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    bot_signature_df['tags'] = bot_signature_df['tags'].astype(str)

    '''
    If a signature matches one of the known bot signatures confidence = 0.6
    '''



    '''
    If an MD5 hash of the byte code of a suspicious smart contract equals 
    the hash of a smart contract that was classified as a bot before, 
    confidence = 0.95
    '''
    contracts_df['to_address_md5'] = contracts_df['to_address_hash']\
                            .apply(lambda x: hashlib.md5(x.encode()).hexdigest())
    
    known_bots_df['to_address_md5'] = known_bots_df['to_address_hash']\
                            .apply(lambda x: hashlib.md5(x.encode()).hexdigest())
    
    bot_contract_query = """
        select 
            to_address_hash,
            'bot' as tag,
            '0.95' as confidence_level
        from contracts_df where to_address_md5 in {}
    """.format(tuple(known_bots_df['to_address_md5']))
    bot_contract_df = sqldf(bot_contract_query)
    bot_contract_df['confidence_level'] = bot_contract_df['confidence_level']\
                                                                    .astype(float)
    bot_contract_df['tags'] = bot_contract_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    bot_contract_df['tags'] = bot_contract_df['tags'].astype(str) 


    '''
    If the byte code of a suspicious smart contract is similar to the byte 
    code of a smart contract that was classified as a bot before
    (with 60% similarity and higher) confidence = 0.7
    '''



    '''
    Mark all callers of the bot smart contract as bots with confidence 1 
    if the number of calls exceeds a certain threshold, 
    if not confidence = 0.6.
    '''
    bot_caller_query = """
        select 
            caller,
            to_address_hash,
            'bot' as tag,
            '1' as confidence_level
        from callers_df 
        where to_address_hash in {}
    """.format(tuple(known_bots_df['to_address_hash']))
    bot_caller_df = sqldf(bot_caller_query)
    bot_caller_df['confidence_level'] = bot_caller_df['confidence_level']\
                                                                    .astype(float)
    
    bot_caller_df['tags'] = bot_caller_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    bot_caller_df['tags'] = bot_caller_df['tags'].astype(str)

    '''
    If a smart contract was deployed by the creator of a smart contract that 
    was classified as a bot before confidence = 0.4.
    '''

    
    bot_contract_df = bot_contract_df.drop(columns=['confidence_level', 'tag'])
    bot_contract_df.insert(0, 'timestamp', pd.to_datetime('now').replace(microsecond=0))

    print(bot_contract_df.to_string())

    bot_signature_df = bot_signature_df.drop(columns=['confidence_level', 'tag'])
    bot_signature_df = bot_signature_df.fillna(0)
    bot_signature_df['invocations'] = bot_signature_df['invocations'].astype(int)
    bot_signature_df.insert(0, 'timestamp', pd.to_datetime('now').replace(microsecond=0))
    
    bot_caller_df = bot_caller_df.drop(columns=['confidence_level', 'tag'])
    bot_caller_df.insert(0, 'timestamp', pd.to_datetime('now').replace(microsecond=0))

    return bot_contract_df, bot_signature_df, bot_caller_df


'''
get data generated from explore stage
'''
def get_tagged_data():
    contracts_query = """
    select *
    from `celo-testnet-production.abhinav.suspicious_contracts`
    """
    contracts_df = (bqclient.query(contracts_query)
                    .result().to_dataframe(create_bqstorage_client=True))
        
    
    signatures_query = """
    select *
    from `celo-testnet-production.abhinav.suspicious_signatures`
    """
    signatures_df = (bqclient.query(signatures_query)
                    .result().to_dataframe(create_bqstorage_client=True))
    
    
    callers_query = """
    select *
    from `celo-testnet-production.abhinav.suspicious_callers`
    """
    callers_df = (bqclient.query(callers_query)
                    .result().to_dataframe(create_bqstorage_client=True))

    return contracts_df, signatures_df, callers_df

# def write_df(input_df, table_name):
#     print('** writing data to BQ **')
#     project_id = 'celo-testnet-production'
#     table_id = 'abhinav.' + table_name

#     if table_name == 'signatures':
#         print('writing to ' + str(table_name))
#         for index, row in input_df.iterrows():
#             signatures_query = """
#                 update `{}`
#                 set tags = "{}"
#                 where from_address_hash = '{}'
#                 and to_address_hash = '{}'
#                 and signature = '{}' 
#                 """.format(project_id + '.' + table_id, 
#                            str(row['tags']), 
#                            row['from_address_hash'], 
#                            row['to_address_hash'], 
#                            row['signature'])
            
#             query_job = bqclient.query(signatures_query)

#             # Wait for query job to finish.
#             query_job.result()
#             print(f"DML query modified {query_job.num_dml_affected_rows} rows.")
#     elif table_name == 'contracts':
#         print('writing to ' + str(table_name))
#         print('number of rows: ' + str(len(input_df)))
#         for index, row in input_df.iterrows():
#             contracts_query = """
#                 update `{}`
#                 set tags = "{}"
#                 where to_address_hash = '{}'
#                 """.format(project_id + '.' + table_id, 
#                            str(row['tags']), 
#                            row['to_address_hash'])
            
#             query_job = bqclient.query(contracts_query)

#             # Wait for query job to finish.
#             query_job.result()
#             print(f"DML query modified {query_job.num_dml_affected_rows} rows.")
#     elif table_name == 'callers':
#         print('writing to ' + str(table_name))
#         for index, row in input_df.iterrows():
#             callers_query = """
#                 update `{}`
#                 set tags = "{}"
#                 where caller = '{}'
#                 and to_address_hash = '{}'
#                 """.format(project_id + '.' + table_id, 
#                            str(row['tags']), 
#                            row['caller'],
#                            row['to_address_hash'])
#             query_job = bqclient.query(callers_query)

#             # Wait for query job to finish.
#             query_job.result()
#             print(f"DML query modified {query_job.num_dml_affected_rows} rows.")
    
#     print("successfully wrote data to {}".format(project_id + '.' + table_id))

def write_df2(input_df, table_name):
    project_id = 'celo-testnet-production'
    table_id = 'abhinav.' + table_name

    pandas_gbq.to_gbq(input_df, table_id, project_id=project_id, if_exists='append')
    print("successfully wrote data to {}".format(project_id + '.' + table_id))

def run(request='request', context='context'):
    contracts, signatures, callers = get_tagged_data()
    bot_contracts, bot_signatures, bot_callers = analyze(contracts, signatures, callers)
    write_df2(bot_contracts, 'contract_attributes')
    write_df2(bot_signatures, 'signature_attributes')
    write_df2(bot_callers, 'callers_attributes')

# for testing purposes
if __name__ == '__main__':
    contracts, signatures, callers = get_tagged_data()
    bot_contracts, bot_signatures, bot_callers = analyze(contracts, signatures, callers)
    write_df2(bot_contracts, 'contract_attributes')
    write_df2(bot_signatures, 'signature_attributes')
    write_df2(bot_callers, 'caller_attributes')


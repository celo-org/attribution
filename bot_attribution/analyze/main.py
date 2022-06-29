from google.cloud import bigquery
import pandas as pd
import pandas_gbq
from pandasql import sqldf
import hashlib

bqclient = bigquery.Client()
def analyze(contracts_df, signatures_df, callers_df):
    # print('CONTRACTS')
    # print(contracts_df.to_string())

    # print('SIGNATURES')
    # print(signatures_df.to_string())

    # print('CALLERS')
    # print(callers_df.to_string())

    '''
    Tag known bots. Acts as a 'seed' for the heuristic
    '''
    known_bots_query = """
        select
            from_address_hash,
            to_address_hash,
            signature,
            invocations,
            'bot' as tag
        from signatures_df
        order by invocations desc
        limit 2
    """

    known_bots_df = sqldf(known_bots_query)
    # print('KNOWN BOTS')
    # print(known_bots_df.to_string())

    '''
    All signatures that belong to a smart contract that was classified as bot 
    confidence = 1
    '''
    bot_signature_query = """
        select distinct
            signature,
            'bot' as tag,
            '1' as confidence_level
        from signatures_df 
        where to_address_hash in {}
    """.format(tuple(known_bots_df['to_address_hash'].to_list()))

    # print(bot_signature_query)
    bot_signature_df = sqldf(bot_signature_query)
    bot_signature_df['confidence_level'] = bot_signature_df['confidence_level']\
                                                                    .astype(float)
    bot_signature_df['tags'] = bot_signature_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    bot_signature_df['tags'] = bot_signature_df['tags'].astype(str)
    
    # print(' ')
    # print('bot_signature_df')
    # print(bot_signature_df.to_string())

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
            'bot' as tag,
            '1' as confidence_level
        from callers_df 
        where to_address_hash in {}
    """.format(tuple(known_bots_df['to_address_hash']))
    bot_caller_df = sqldf(bot_caller_query)
    bot_caller_df['confidence_level'] = bot_caller_df['confidence_level']\
                                                                    .astype(float)
    
    bot_caller_df['tags'] = bot_caller_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    # print('DEBUG 115')
    bot_caller_df['tags'] = bot_caller_df['tags'].astype(str)
    print(bot_caller_df.to_string())




    '''
    If a smart contract was deployed by the creator of a smart contract that 
    was classified as a bot before confidence = 0.4.
    '''

    return bot_contract_df, bot_signature_df, bot_caller_df



def get_tagged_data():
    # get tables generated from exploration stage
    contracts_query = """
    select *
    from `celo-testnet-production.abhinav.contracts`
    """
    contracts_df = (bqclient.query(contracts_query)
                    .result().to_dataframe(create_bqstorage_client=True))
        
    
    signatures_query = """
    select *
    from `celo-testnet-production.abhinav.signatures`
    """
    signatures_df = (bqclient.query(signatures_query)
                    .result().to_dataframe(create_bqstorage_client=True))
    
    
    callers_query = """
    select *
    from `celo-testnet-production.abhinav.callers`
    """
    callers_df = (bqclient.query(callers_query)
                    .result().to_dataframe(create_bqstorage_client=True))

    return contracts_df, signatures_df, callers_df

def write_df(input_df, table_name):
    project_id = 'celo-testnet-production'
    table_id = 'abhinav.' + table_name

    pandas_gbq.to_gbq(input_df, table_id, project_id=project_id, if_exists='append')
    print("successfully wrote data to {}".format(project_id + '.' + table_id))


if __name__ == '__main__':
    contracts, signatures, callers = get_tagged_data()
    bot_contracts, bot_signatures, bot_callers = analyze(contracts, signatures, callers)
    write_df(bot_contracts, 'bot_contracts')
    write_df(bot_signatures, 'bot_signatures')
    write_df(bot_callers, 'bot_callers')


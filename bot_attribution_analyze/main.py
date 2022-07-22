from google.cloud import bigquery
import pandas as pd
import pandas_gbq
from pandasql import sqldf
import hashlib
import random
import datetime
import pytz
from difflib import SequenceMatcher

bqclient = bigquery.Client()
def analyze(contracts_df, signatures_df, callers_df):
    '''
    Tag known bot. Acts as a 'seed' for the heuristic
    '''
    known_bots_query = """
        select
            *
        from signatures_df
        order by invocations desc
        limit 1000
    """
    known_bots_df = sqldf(known_bots_query)

    '''
    All signatures that belong to a smart contract that was classified as bot 
    confidence = 1
    '''
    bot_signature_query = """
        select distinct
            to_address_hash,
            signature,
            invocations,
            'bot' as tag,
            '1' as confidence_level
        from signatures_df 
        where to_address_hash in {}
    """.format(tuple(known_bots_df['to_address_hash'].to_list()))

    bot_signature_df = sqldf(bot_signature_query)
    
    signatures_df = signatures_df[~signatures_df.signature.isin(bot_signature_df.signature)]

    bot_signature_df['confidence_level'] = bot_signature_df['confidence_level'].astype(float)
    bot_signature_df['tags'] = bot_signature_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    bot_signature_df['tags'] = bot_signature_df['tags'].astype(str)
    '''
    If a signature matches one of the known bot signatures confidence = 0.6
    '''
    signature_match_query = """
        select distinct
            b.signature,
            b.invocations,
            'bot' as tag,
            '0.6' as confidence_level
        from signatures_df s
        join bot_signature_df b
        on s.signature = b.signature
        where b.confidence_level >= 0.9
    """

    signature_match_df = sqldf(signature_match_query)
    signature_match_df['confidence_level'] = signature_match_df['confidence_level'].astype(float)
    signature_match_df['tags'] = signature_match_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    signature_match_df['tags'] = signature_match_df['tags'].astype(str)
    
    bot_signature_df = pd.concat([bot_signature_df, signature_match_df])

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
            '0.95' as confidence_level,
            block_timestamp,
            updated_at
        from contracts_df where to_address_md5 in {}
    """.format(tuple(known_bots_df['to_address_md5']))
    bot_contract_df = sqldf(bot_contract_query)

    bot_contract_df['confidence_level'] = bot_contract_df['confidence_level'].astype(float)
    bot_contract_df['tags'] = bot_contract_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    bot_contract_df['tags'] = bot_contract_df['tags'].astype(str) 

    '''
    If the byte code of a suspicious smart contract is similar to the byte 
    code of a smart contract that was classified as a bot before
    (with 60% similarity and higher) confidence = 0.7
    '''
    suspicious_contracts_query = """
        select 
            *
        from contracts_df
        where tags = "('suspicious', '1')"
    """
    suspicious_contracts_df = sqldf(suspicious_contracts_query)

    bot_contract_list = list(bot_contract_df['to_address_hash'].drop_duplicates())
    
    for index, row in contracts_df.iterrows():
        score = 0 
        for bot_contract in bot_contract_list:            
            best_match = round(SequenceMatcher(None, row['to_address_hash'], bot_contract).ratio(), 2)
            score = max(score, best_match)            
        if score > 0.6:
            suspicious_contracts_df.loc[index, 'tags'] = f"('bot', '0.7')"
    
    suspicious_contracts_df = suspicious_contracts_df.drop_duplicates()
    bot_contract_df = pd.concat([bot_contract_df, suspicious_contracts_df[suspicious_contracts_df['tags']
                                                                                   .str.contains("bot")]])

    '''
    Mark all callers of the bot smart contract as bots with confidence 1 
    if the number of calls exceeds a certain threshold, 
    if not confidence = 0.6.
    '''
    callers_df = callers_df.drop_duplicates(subset=['caller', 'to_address_hash', 'tags'])
    signatures_df = signatures_df.drop_duplicates()

    bot_caller_query = """
        select 
            caller,
            c.to_address_hash,
            'bot' as tag,
            case when s.invocations > 200 then '1' else '0.6' end as confidence_level 
        from callers_df c
        left join signatures_df s
        on s.to_address_hash = c.to_address_hash
        where c.to_address_hash in {}
    """.format(tuple(known_bots_df['to_address_hash']))
    bot_caller_df = sqldf(bot_caller_query)
    bot_caller_df['confidence_level'] = bot_caller_df['confidence_level'].astype(float)    
    bot_caller_df['tags'] = bot_caller_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    bot_caller_df['tags'] = bot_caller_df['tags'].astype(str)

    '''
    Inhumane frequency - 5 txs in 1 minute
    confidence_level = 0.7
    '''
    transaction_query_string = """
        with invocation_table as 
            (select 
                to_address_hash, 
                from_address_hash,
                SUBSTR(`input`, 0, 10) as signature,
                COUNT(1) as invocations,
                datetime_trunc(block_timestamp, MINUTE) as block_timestamp_minute
            from `celo-testnet-production.analytics_general.transactions`
            where block_timestamp > TIMESTAMP_ADD(CURRENT_TIMESTAMP(), INTERVAL -7 DAY)
            group by 1, 2, 3, 5)
        select *
        from invocation_table
        where invocations > 5
    """

    transaction_df = (bqclient.query(transaction_query_string)
                    .result().to_dataframe(create_bqstorage_client=True))

    match_caller_query = """
        select
            b.caller,
            b.to_address_hash,
            'bot' as tag,
            '0.7' as confidence_level
        from bot_caller_df b
        left join transaction_df t
        on b.to_address_hash = t.from_address_hash
        where tags = "('suspicious', '1')"
    """
    match_caller_df = sqldf(match_caller_query)

    if not match_caller_df.empty:
        bot_caller_df = pd.concat([bot_caller_df, match_caller_df])
    

    print(f'bot_contract_df: {len(bot_contract_df.index)} records')
    
    print(f'bot_signature_df: {len(bot_signature_df.index)} records')

    print(f'bot_caller_df: {len(bot_caller_df.index)} records')

    '''
    whitelist join all the dataframes we have against this df/table, if match then remove
    '''
    smart_contract_query = """
        select distinct
            id,
            name,
            address_hash
        from celo-testnet-production.analytics_general.smart_contracts
    """
    smart_contract_df = (bqclient.query(smart_contract_query)
                    .result().to_dataframe(create_bqstorage_client=True))

    bot_contract_df = bot_contract_df[~bot_contract_df.to_address_hash.isin(smart_contract_df.address_hash)]
    bot_signature_df = bot_signature_df[~bot_signature_df.to_address_hash.isin(smart_contract_df.address_hash)]    
    bot_caller_df = bot_caller_df[~bot_caller_df.to_address_hash.isin(smart_contract_df.address_hash)]
    
    bot_contract_df.insert(0, 'timestamp', pd.to_datetime('now').replace(microsecond=0))
    bot_contract_df = bot_contract_df.drop_duplicates(subset=['to_address_hash'])
    
    bot_signature_df = bot_signature_df.fillna(0)
    bot_signature_df['invocations'] = bot_signature_df['invocations'].astype(int)
    bot_signature_df.insert(0, 'timestamp', pd.to_datetime('now').replace(microsecond=0))
    bot_signature_df = bot_signature_df.drop_duplicates(subset=['to_address_hash'])
    
    bot_caller_df.insert(0, 'timestamp', pd.to_datetime('now').replace(microsecond=0))
    bot_caller_df = bot_caller_df.drop_duplicates(subset=['to_address_hash'])

    return bot_contract_df, bot_signature_df, bot_caller_df

'''
get data generated from explore stage
'''
def get_tagged_data():
    contracts_query = """
    select *
    from `celo-testnet-production.analytics_attribution.contracts`
    where tags like '%suspicious%' 
    """
    contracts_df = (bqclient.query(contracts_query)
                    .result().to_dataframe(create_bqstorage_client=True))

    signatures_query = """
    select *
    from `celo-testnet-production.analytics_attribution.signatures`
    where tags like '%suspicious%'
    """
    signatures_df = (bqclient.query(signatures_query)
                    .result().to_dataframe(create_bqstorage_client=True))
    
    callers_query = """
    select *
    from `celo-testnet-production.analytics_attribution.callers`
    where tags like '%suspicious%'
    """
    callers_df = (bqclient.query(callers_query)
                    .result().to_dataframe(create_bqstorage_client=True))

    return contracts_df, signatures_df, callers_df

def write_df(input_df, table):
    project = 'celo-testnet-production'
    dataset = 'analytics_attribution'
    temp_table = write_temp_table(input_df, project, dataset, table)

    query = ""
    if table == 'callers-test3':
        query = f"""
            merge into `{project}.{dataset}.{table}` as t
            using `{project}.{temp_table}` as s
            on t.caller = s.caller
            and t.to_address_hash = s.to_address_hash
            and t.caller = s.caller
            when matched then
                update set tags = s.tags, updated_at = CURRENT_TIMESTAMP()
            when not matched then
                insert (caller, to_address_hash, tags)
                values (caller, to_address_hash, tags)
        """
    elif table == 'signatures-test3':
        query = f"""
            merge into `{project}.{dataset}.{table}` as t
            using `{project}.{temp_table}` as s
            on t.signature = s.signature
            and t.to_address_hash = s.to_address_hash
            when matched then
                update set tags = s.tags, updated_at = CURRENT_TIMESTAMP()
            when not matched then
                insert (to_address_hash, signature, invocations, tags)
                values (to_address_hash, signature, invocations, tags)
        """
    elif table == 'contracts-test3':
        query = f"""
            merge into `{project}.{dataset}.{table}` as t
            using `{project}.{temp_table}` as s
            on t.to_address_hash = s.to_address_hash
            when matched then
                update set tags = s.tags, updated_at = CURRENT_TIMESTAMP()
            when not matched then
                insert (to_address_hash, tags)
                values (to_address_hash, tags)
        """
    print(query)
    query_job = bqclient.query(query)

    # Wait for query job to finish.
    query_job.result()
    print(f"DML query modified {query_job.num_dml_affected_rows} rows.")

def write_temp_table(input_df, project, dataset, table):
    prefix = "temp"
    suffix = random.randint(10000, 99999)

    temp_table_name = f"{dataset}.{prefix}_{table}_{suffix}"
    tmp_table_def = bigquery.Table(project + '.' + temp_table_name)
    tmp_table_def.expires = datetime.datetime.now(pytz.utc) + datetime.timedelta(
        hours=1
    )

    pandas_gbq.to_gbq(input_df, temp_table_name, project_id=project)
    print("successfully wrote data to {}".format(project + '.' + temp_table_name))

    return f"{dataset}.{prefix}_{table}_{suffix}"

def run(request='request', context='context'):
    contracts, signatures, callers = get_tagged_data()
    bot_contracts, bot_signatures, bot_callers = analyze(contracts, signatures, callers)
    
    if not bot_contracts.empty:
        write_df(bot_contracts, 'contracts')
    
    if not bot_signatures.empty:
        write_df(bot_signatures, 'signatures')

    if not bot_callers.empty:
        write_df(bot_callers, 'callers')


# for testing purposes
if __name__ == '__main__':
    contracts, signatures, callers = get_tagged_data()
    bot_contracts, bot_signatures, bot_callers = analyze(contracts, signatures, callers)
    
    if not bot_contracts.empty:
        write_df(bot_contracts, 'contracts-test3')
    
    if not bot_signatures.empty:
        write_df(bot_signatures, 'signatures-test3')
    
    if not bot_callers.empty:
        write_df(bot_callers, 'callers-test3')
from google.cloud import bigquery
import pandas as pd
import pandas_gbq
from pandasql import sqldf


bqclient = bigquery.Client()

'''
pull in rpl_transaction data, and place into pandas dataframe
'''
def get_transactions():
    print(" *** pulling latest transaction data from rpl_transactions *** ")
    
    # Download query results.
    query_string = """
    select *
    from `celo-testnet-production.abhinav.rpl_transactions_subset`
    limit 10000
    """

    df = (bqclient.query(query_string)
                    .result().to_dataframe(create_bqstorage_client=True))
    
    return df
    


def explore(transactions_df):
    '''
    Identify the most frequently called function signatures. Tag them as “suspicious”.
    most frequently = top 10?
    '''
    print(' ')
    print(" *** finding frequently called signatures *** ")
    signatures_query = """
        select          
            from_address_hash, 
            to_address_hash, 
            SUBSTR(`input`, 0, 10) as signature,
            COUNT(1) as invocations,
            '1' as confidence_level,
            'suspicious' as tag,
            block_timestamp
        from transactions_df
        group by 1, 2, 3 
        order by 4 DESC
        limit 10
    """

    signatures_df = sqldf(signatures_query)
    signatures_df['tags'] = signatures_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    signatures_df['tags'] = signatures_df['tags'].astype(str)
    

    '''
    Tag smart contracts that these functions belong to as “suspicious”.
    '''
    print(' ')
    print(" *** finding smart contracts of frequent functions *** ")
    contract_query = """
        select distinct
            to_address_hash,
            tags
        from signatures_df
    """

    contracts_df = sqldf(contract_query)

    '''
    Tag all the addresses that call these functions a lot of times as “suspicious”.
    '''
    print(' ')
    print(" *** finding frequent functions callers *** ")
    callers_query = """
        select          
            from_address_hash as caller,
            to_address_hash, 
            tags 
        from signatures_df
        limit 10
    """
    
    callers_df = sqldf(callers_query)

    '''
    Tag creators of “suspicious” smart contracts as “suspicious”.
    '''
    print(' ')
    print(" *** finding creators of smart contracts *** ")

    suspicious_contracts_query = """
        SELECT *
        FROM `celo-testnet-production.abhinav.rpl_transactions_subset`
        where created_contract_address_hash in {}
    """.format(tuple(contracts_df['to_address_hash'].tolist()))

    suspicious_contracts_df = bqclient.query(suspicious_contracts_query)\
                                .result().to_dataframe(create_bqstorage_client=True)

    creators_query = """
        select 
            from_address_hash,
            '1' as confidence_level,
            'suspicious' as tag
        from suspicious_contracts_df
    """
    creators_df = sqldf(creators_query)
    creators_df['tags'] = creators_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    creators_df['tags'] = creators_df['tags'].astype(str)

    '''
    Tag all other smart contracts created by creators of “suspicious” smart contracts as “suspicious”.
    '''
    print(' ')
    print(" *** finding smart contracts of suspicious creators *** ")
    suspicious_creator_contract_query = """
        select
            created_contract_address_hash as to_address_hash,
            '1' as confidence_level,
            'suspicious' as tag
        from suspicious_contracts_df where from_address_hash in ((select from_address_hash from creators_df))
    """

    suspicious_creator_contract_df = sqldf(suspicious_creator_contract_query)
    suspicious_creator_contract_df['tags'] = suspicious_creator_contract_df[['tag', 'confidence_level']].apply(tuple, axis=1)
    suspicious_creator_contract_df['tags'] = suspicious_creator_contract_df['tags'].astype(str)
    
    contracts_df = pd.concat([contracts_df, suspicious_creator_contract_df])

    contracts_df = contracts_df.drop(columns=['confidence_level', 'tag'])
    signatures_df = signatures_df.drop(columns=['confidence_level', 'tag'])

    print('successfully explored transaction data')
    return contracts_df, signatures_df, callers_df

def write_df(transactions_df, table_name):
    project_id = 'celo-testnet-production'
    table_id = 'abhinav.' + table_name

    pandas_gbq.to_gbq(transactions_df, table_id, project_id=project_id, if_exists='append')
    print("successfully wrote data to {}".format(project_id + '.' + table_id))


def run(request='request', context='context'):
    df_results = get_transactions()
    contracts_df, signatures_df, callers_df = explore(df_results)
    write_df(contracts_df, 'suspicious_contracts')
    write_df(signatures_df, 'suspicious_signatures') 
    write_df(callers_df, 'suspicious_callers')

# for testing purposes
if __name__ == '__main__':
    df_results = get_transactions()
    contracts_df, signatures_df, callers_df = explore(df_results)
    write_df(contracts_df, 'suspicious_contracts')
    write_df(signatures_df, 'suspicious_signatures') 
    write_df(callers_df, 'suspicious_callers')
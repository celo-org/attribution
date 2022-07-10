from google.cloud import bigquery
import pandas as pd
import pandas_gbq
from pandasql import sqldf


bqclient = bigquery.Client()

'''
pull in rpl_transaction data, and place into pandas dataframe
'''
def get_transactions(request, context):
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
    


def explore(input_df):
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
            'suspicious' as tag 
        from input_df
        group by 1, 2, 3 
        order by 4 DESC
        limit 10
    """


    signatures_df = sqldf(signatures_query)    
    print(" * signatures_df *" )
    print(signatures_df.to_string())

    # tags = {'location': 'London','tag': {'suspicious':1, 'bot':0.95}}
    # tag_df = pd.json_normalize(tags,max_level=0)
    # print(" * tag_df *" )
    # print(tag_df.to_string())

    '''
    Tag smart contracts that these functions belong to as “suspicious”.
    '''
    print(' ')
    print(" *** finding smart contracts of frequent functions *** ")
    contract_query = """
        select distinct
            to_address_hash,
            tag 
        from signatures_df
    """

    contracts_df = sqldf(contract_query)
    print(" * contracts_df * ")
    print(contracts_df.to_string())


    '''
    Tag all the addresses that call these functions a lot of times as “suspicious”.
    '''
    print(' ')
    print(" *** finding frequent functions callers *** ")
    callers_query = """
        select          
            from_address_hash as caller,
            to_address_hash, 
            'suspicious' as tag 
        from signatures_df
        limit 10
    """
    
    callers_df = sqldf(callers_query)
    print(" * callers_df * ")
    print(callers_df.to_string())


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

    print(suspicious_contracts_query)

    suspicious_contracts_df = (bqclient.query(suspicious_contracts_query)
                    .result().to_dataframe(create_bqstorage_client=True))
    print(" * suspicious_contracts_df * ")    

    creators_query = """
        select 
            from_address_hash,
            'suspicious' as tag
        from suspicious_contracts_df
    """
    # where created_contract_address_hash in ((select to_address_hash from contracts_df))
    creators_df = sqldf(creators_query)
    print(" * creators_df * ")
    print(creators_df.to_string())


    '''
    Tag all other smart contracts created by creators of “suspicious” smart contracts as “suspicious”.
    '''
    print(' ')
    print(" *** finding smart contracts of suspicious creators *** ")
    suspicious_creator_contract_query = """
        select
            created_contract_address_hash as to_address_hash,
            'suspicious' as tag
        from suspicious_contracts_df where from_address_hash in ((select from_address_hash from creators_df))
    """

    suspicious_creator_contract_df = sqldf(suspicious_creator_contract_query)
    print(" * suspicious_creator_contract_df * ")
    print(suspicious_creator_contract_df.to_string())

    contracts_df = contracts_df.append(suspicious_creator_contract_df)
    print("RETURNING")
    print(" * contracts_df * ")
    print(contracts_df.to_string())

    print(" * signatures_df * ")
    print(signatures_df.to_string())

    print(" * callers_df * ")
    print(callers_df.to_string())

    print('successfully explored transaction data')
    return contracts_df, signatures_df, callers_df




# function to write a df to BQ
def write_df(input_df, table_name):
    project_id = 'celo-testnet-production'
    table_id = 'abhinav.' + table_name

    pandas_gbq.to_gbq(input_df, table_id, project_id=project_id, if_exists='append')
    print("successfully wrote data to {}".format(project_id + '.' + table_id))



if __name__ == '__main__':
    df_results = get_transactions(request, context='context')
    contracts_df, signatures_df, callers_df = explore(df_results)
    write_df(contracts_df, 'contracts')
    write_df(signatures_df, 'signatures') 
    write_df(callers_df, 'callers')
from google.cloud import bigquery
import pandas as pd
import pandas_gbq
from pandasql import sqldf


bqclient = bigquery.Client()

'''
pull in rpl_transaction data, and place into pandas dataframe
'''
def get_data(context):
    print(" *** get data from appropriate source tables *** ")
    
    # Download query results.
    query_string = """
        select *
        from `celo-testnet-production.blockscout_data.rpl_transactions`
        limit 10000
    """

    df = (bqclient.query(query_string)
                    .result().to_dataframe(create_bqstorage_client=True))
    return df
    


def analyze_data(input_df):
    '''
    Below is an example of how to use pandasql to query existing data frames
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
    return contracts_df



def write_df(input_df, table_name):
    '''
    This function converts the contents of your dataframe (including headers) into a BQ table
    '''
    project_id = 'celo-testnet-production'
    table_id = 'dataset_name.' + table_name

    pandas_gbq.to_gbq(input_df, table_id, project_id=project_id, if_exists='append')
    print("successfully wrote data to {}".format(project_id + '.' + table_id))



if __name__ == '__main__':
    df_results = get_data(context='context')
    df_to_table = explore(df_results)
    write_df(df_to_table, 'table_name')
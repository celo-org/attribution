from google.cloud import bigquery
import pandas
import pandas_gbq

'''
pull in rpl_transaction data, and place into pandas dataframe
'''
def get_transactions(context):
    print("pulling latest transaction data from rpl_transactions")
    bqclient = bigquery.Client()

    # Download query results.
    query_string = """
    SELECT * 
    FROM `celo-testnet-production.abhinav.rpl_transactions_subset`
    limit 10000
    """

    df = (bqclient.query(query_string)
                    .result().to_dataframe(create_bqstorage_client=True))
    
    return df
    

'''
Identify the most frequently called function signatures. Tag them as “suspicious”.
most frequently = top 10?
'''


'''
Tag smart contracts that these functions belong to as “suspicious”.
'''


'''
Tag all the addresses that call these functions a lot of times as “suspicious”.
'''


'''
Tag creators of “suspicious” smart contracts as “suspicious”.
'''


'''
Tag all other smart contracts created by creators of “suspicious” smart contracts as “suspicious”.
'''

# function to write a df to BQ
def write_df(input_df):
    project_id = 'celo-testnet-production'
    table_id = 'abhinav.test_write'


    pandas_gbq.to_gbq(input_df, table_id, project_id=project_id, if_exists='append')
    print("successfully write df to bq")



if __name__ == '__main__':
    df_results = get_transactions()
    write_df(df_results)
    # explore_data(df_results)
    # write dfs to BQ
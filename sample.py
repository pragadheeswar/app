import numpy as np
import pickle
import pandas as pd
import random

df = pd.read_pickle('data.pkl')

normaldf = df[df['labels']==0]
dosdf = df[df['labels']==1]
r2ldf = df[df['labels']==2]
u2rdf = df[df['labels']==3]
probedf = df[df['labels']==4]


def generate_ip():
    # Generate random numbers for each part of the IP address
    parts = [str(random.randint(0, 255)) for _ in range(4)]
    
    # Join the parts together with periods to form the IP address
    ip_address = '.'.join(parts)
    
    return ip_address

value = [12,3,2,1,2]

list = [normaldf,dosdf,r2ldf,u2rdf,probedf]

for i in range(len(list)):
    list[i] = list[i].drop(columns=['labels'])
    list[i].insert(0, 'ip', None)

def get_df(df,no):
    data = df.sample(n=no)
    for index, row in data.iterrows():
        data.at[index, 'ip'] = generate_ip()
    
    return data


result = pd.DataFrame()

for i in range(len(list)):
    df = get_df(list[i],value[i])
    result = pd.concat([df, result])

result = result.sample(frac=1).reset_index(drop=True)

result.to_csv("sample_trafic.csv", index=False, header=True)
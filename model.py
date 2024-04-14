
import numpy as np
import pickle
import itertools
import pandas as pd
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, confusion_matrix



import sklearn
print(sklearn.__version__)

train = pd.read_csv('KDDTrain+.txt')

columns = (['duration'
,'protocol_type'
,'service'
,'flag'
,'src_bytes'
,'dst_bytes'
,'land'
,'wrong_fragment'
,'urgent'
,'hot'
,'num_failed_logins'
,'logged_in'
,'num_compromised'
,'root_shell'
,'su_attempted'
,'num_root'
,'num_file_creations'
,'num_shells'
,'num_access_files'
,'num_outbound_cmds'
,'is_host_login'
,'is_guest_login'
,'count'
,'srv_count'
,'serror_rate'
,'srv_serror_rate'
,'rerror_rate'
,'srv_rerror_rate'
,'same_srv_rate'
,'diff_srv_rate'
,'srv_diff_host_rate'
,'dst_host_count'
,'dst_host_srv_count'
,'dst_host_same_srv_rate'
,'dst_host_diff_srv_rate'
,'dst_host_same_src_port_rate'
,'dst_host_srv_diff_host_rate'
,'dst_host_serror_rate'
,'dst_host_srv_serror_rate'
,'dst_host_rerror_rate'
,'dst_host_srv_rerror_rate'
,'labels'
,'level'])

train.columns = columns
train.columns = columns


train.head()



from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()
train['protocol_type'] = le.fit_transform(train['protocol_type'])


for i, label in enumerate(le.classes_):
    print(f"{i}: {label}")

train['labels'].unique()

dos_attacks=["snmpgetattack","back","land","neptune","smurf","teardrop","pod","apache2","udpstorm","processtable","mailbomb"]
r2l_attacks=["snmpguess","worm","httptunnel","named","xlock","xsnoop","sendmail","ftp_write","guess_passwd","imap","multihop","phf","spy","warezclient","warezmaster"]
u2r_attacks=["sqlattack","buffer_overflow","loadmodule","perl","rootkit","xterm","ps"]
probe_attacks=["ipsweep","nmap","portsweep","satan","saint","mscan"]

attack_labels = ['Normal','DoS','r2l','u2r','Probe']

def map_attack(attack):
    if attack in dos_attacks:
        # dos_attacks map to 1
        attack_type = 1
    elif attack in r2l_attacks:
        # probe_attacks mapt to 2
        attack_type = 2
    elif attack in u2r_attacks:
        # privilege escalation attacks map to 3
        attack_type = 3
    elif attack in probe_attacks:
        # remote access attacks map to 4
        attack_type = 4
    else:
        # normal maps to 0
        attack_type = 0

    return attack_type

attack_map = train.labels.apply(map_attack)
train['labels'] = attack_map


train.head()

from sklearn.preprocessing import LabelEncoder
le=LabelEncoder()
train['service']=le.fit_transform(train['service'].astype("str"))
train['service'].value_counts()
for i, label in enumerate(le.classes_):
    print(f"{i}: {label}")

from sklearn.preprocessing import LabelEncoder
le=LabelEncoder()
train['flag']=le.fit_transform(train['flag'].astype("str"))
train['flag'].value_counts()
for i, label in enumerate(le.classes_):
    print(f"{i}: {label}")

x_train= train[['duration',
                 'protocol_type',
                  'flag',
                 'dst_bytes',
                 'src_bytes',
                 'land',
                 'is_guest_login',
                 'is_host_login',
                 'dst_host_count',
                 'dst_host_srv_count']]

train = train[['duration',
                 'protocol_type',
                  'flag',
                 'dst_bytes',
                 'src_bytes',
                 'land',
                 'is_guest_login',
                 'is_host_login',
                 'dst_host_count',
                 'dst_host_srv_count',
               'labels']]

train.tail()





train

train[(train['labels']==0)].head()

train[(train['labels']==1)].head()

train[(train['labels']==2)].head()

train[(train['labels']==3)].head()

train[(train['labels']==4)].head()

x_train

y_train=train['labels']

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(x_train, y_train, test_size=0.3, random_state=9)
print(X_train.shape)
print(X_test.shape)


from sklearn.ensemble import RandomForestClassifier

classifier = RandomForestClassifier()
classifier.fit(X_train.to_numpy(), y_train)

classifier.score(X_train.to_numpy(),y_train)



from xgboost import XGBClassifier

xgb = XGBClassifier()
xgb.fit(X_train.to_numpy(), y_train)
xgb.score(X_train.to_numpy(), y_train)




from sklearn.ensemble import VotingClassifier

estimators = [('RandomForest', classifier), ('XGBoost', xgb)]

ensemble = VotingClassifier(estimators)
ensemble.fit(X_train, y_train)
ensemble.score(X_train, y_train)





first_row_as_numpy_array = X_train.iloc[88].to_numpy()

X_train.shape

first_row_as_numpy_array.size



predicted_label = classifier.predict_proba([first_row_as_numpy_array])
print(predicted_label)

predicted_label.sum()



import pickle


with open('rf.pkl', 'wb') as f:
    pickle.dump(classifier, f)

with open('xg.pkl', 'wb') as f:
    pickle.dump(xgb, f)


with open('ensemble.pkl', 'wb') as f:
    pickle.dump(ensemble, f)

train.to_pickle('data.pkl')



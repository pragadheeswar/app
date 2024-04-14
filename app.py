from flask import Flask, render_template, request, redirect,url_for
import numpy as np
import pickle
import pandas as pd
from flask import jsonify
from xgboost import XGBClassifier
import os
from collections import Counter

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('rf.pkl', 'rb') as f:
    rf = pickle.load(f)

with open('xg.pkl', 'rb') as f:
    xg = pickle.load(f)

with open('ensemble.pkl', 'rb') as f:
    ensemble = pickle.load(f)

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route("/", methods=['POST','GET'])
def login():
  if request.method == "POST":
    username = request.form["username"]
    password = request.form["password"]
    if username == "admin" and password == "admin":
      return redirect('/index')
    else:
      return "Invalid username or password"
  else:
    return render_template("login.html")


@app.route('/index')
def index():
    return render_template('form.html')

@app.route('/submit', methods=['POST'])
def submit():
    duration = int(request.form['duration'])
    protocol_type = int(request.form['protocol_type'])
    flag = int(request.form['flag'])
    src_byter = int(request.form['src_byte'])
    destination_byter = int(request.form['destination_byte'])
    land = int(request.form['land'])
    is_host_login = int(request.form['is_host_login'])
    is_guest_login = int(request.form['is_guest_login'])
    same_destn_count = int(request.form['same_destn_count'])
    same_port_count = int(request.form['same_port_count'])

    form_data = np.array([[duration, protocol_type, flag, destination_byter,src_byter, land, is_guest_login,
                            is_host_login, same_destn_count, same_port_count]])
    attack_labels = ['Normal','DoS','R2L','U2L','Probe']

    prediction_rf = rf.predict_proba(form_data)
    prediction_xg = xg.predict_proba(form_data)
    rounded_probabilities_rf = np.round(prediction_rf, 2)
    rounded_probabilities_xg = np.round(prediction_xg, 2)
    prediction = attack_labels[ensemble.predict(form_data)[0]]
    return render_template("barchart.html",prediction=prediction, prediction_rf=rounded_probabilities_rf[0].tolist(),prediction_xg=rounded_probabilities_xg[0].tolist())
data = [23, 45, 56, 78, 32]
@app.route('/chart')
def chart():
    return render_template('chart.html', data=data)

df = pd.read_pickle('data.pkl')

normaldf = df[df['labels']==0]
dosdf = df[df['labels']==1]
r2ldf = df[df['labels']==2]
u2rdf = df[df['labels']==3]
probedf = df[df['labels']==4]


def return_sample(df):
    row = df.sample(n=1)
    row.drop(columns='labels', inplace=True)
    json_result = row.to_json(orient='records')
    

    return jsonify(json_result)


@app.route('/normal')
def normal():
    return return_sample(normaldf)

@app.route('/dos')
def dos():
    return return_sample(dosdf)

@app.route('/r2l')
def r2l():
    return return_sample(r2ldf)

@app.route('/u2r')
def u2r():
    return return_sample(u2rdf)

@app.route('/probe')
def probe():
    return return_sample(probedf)

@app.route('/file')
def file():
    return render_template("file.html")

@app.route('/upload', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        
        file = request.files['file']
        
        if file.filename == '':
            return 'No selected file'
        
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            df = pd.read_csv(file_path, header=0)
            dfsend= df.copy()
            protocol_map = {0: 'ICMP', 1: 'TCP', 2: 'UDP'}
            flag_map = {0: 'OTH', 1: 'REJ', 2: 'RSTO', 3: 'RSTOS0', 4: 'RSTR', 5: 'S0', 6: 'S1', 7: 'S2', 8: 'S3', 9: 'SF', 10: 'SH'}
            dfsend['protocol_type'] = dfsend['protocol_type'].replace(protocol_map)
            dfsend['flag'] = dfsend['flag'].replace(flag_map)
            attack_labels = ['Normal','DoS','R2L','U2R','Probe']
            for index,row in dfsend.iterrows():
                print(row['ip'])
            ip_list = df.pop('ip').tolist()
            prediction_list = rf.predict(df.to_numpy()).tolist()
            print(prediction_list)
            lable_list = [attack_labels[index] for index in prediction_list]
            return render_template('analyst.html', pre= prediction_list,df=dfsend,lable_list=lable_list,protocol_count=dfsend['protocol_type'].tolist())



if __name__ == '__main__':
    app.run(debug=True, port=5002)

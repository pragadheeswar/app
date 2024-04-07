from flask import Flask, render_template, request
import numpy as np
import pickle
import pandas as pd
from flask import jsonify
from xgboost import XGBClassifier

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('rf.pkl', 'rb') as f:
    rf = pickle.load(f)

with open('xg.pkl', 'rb') as f:
    xg = pickle.load(f)

app = Flask(__name__)

@app.route('/')
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

    # Convert form data into a NumPy array
    form_data = np.array([[duration, protocol_type, flag, src_byter, destination_byter, land, 
                            is_host_login, is_guest_login, same_destn_count, same_port_count]])
    attack_labels = ['Normal','DoS','r2l','u2r','Probe']
    # Make prediction using the loaded model
    prediction_rf = rf.predict_proba(form_data)
    prediction_xg = xg.predict_proba(form_data)
    rounded_probabilities_rf = np.round(prediction_rf, 2)
    rounded_probabilities_xg = np.round(prediction_xg, 2)
    prediction = attack_labels[rf.predict(form_data)[0]]
    print(rounded_probabilities_rf)



    # Do something with the prediction, for example, return it as a response
    return render_template("barchart.html",prediction=prediction, prediction_rf=rounded_probabilities_rf[0].tolist())
data = [23, 45, 56, 78, 32]
@app.route('/chart')
def chart():
    # Render the HTML template with data
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
    # Converting the selected row to JSON
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

if __name__ == '__main__':
    app.run(debug=True, port=5002)
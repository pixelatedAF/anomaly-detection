from django.db.models import Count
from django.db.models import Q
from django.shortcuts import render, redirect, get_object_or_404
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score, confusion_matrix, precision_recall_curve
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, LSTM, Dropout
from tensorflow.keras.utils import to_categorical
import matplotlib.pyplot as plt
 
from sklearn.metrics import classification_report, confusion_matrix, f1_score, recall_score, precision_score, roc_curve, precision_recall_curve
# Load Data
# Create your views here.
from Remote_User.models import ClientRegister_Model,Advanced_Intrusion_type_prediction,detection_ratio,detection_accuracy

def login(request):


    if request.method == "POST" and 'submit1' in request.POST:

        username = request.POST.get('username')
        password = request.POST.get('password')
        try:
            enter = ClientRegister_Model.objects.get(username=username,password=password)
            request.session["userid"] = enter.id

            return redirect('ViewYourProfile')
        except:
            pass

    return render(request,'RUser/login.html')

def index(request):
    return render(request, 'RUser/index.html')

def Add_DataSet_Details(request):

    return render(request, 'RUser/Add_DataSet_Details.html', {"excel_data": ''})


def Register1(request):

    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        phoneno = request.POST.get('phoneno')
        country = request.POST.get('country')
        state = request.POST.get('state')
        city = request.POST.get('city')
        address = request.POST.get('address')
        gender = request.POST.get('gender')
        ClientRegister_Model.objects.create(username=username, email=email, password=password, phoneno=phoneno,
                                            country=country, state=state, city=city,address=address,gender=gender)

        obj = "Registered Successfully"
        return render(request, 'RUser/Register1.html',{'object':obj})
    else:
        return render(request,'RUser/Register1.html')

def ViewYourProfile(request):
    userid = request.session['userid']
    obj = ClientRegister_Model.objects.get(id= userid)
    return render(request,'RUser/ViewYourProfile.html',{'object':obj})


def Predict_Advanced_Intrusion_Type(request):
    if request.method == "POST":

        if request.method == "POST":

            timestamp= request.POST.get('timestamp')
            src_ip= request.POST.get('src_ip')
            src_port= request.POST.get('src_port')
            dst_ip= request.POST.get('dst_ip')
            dst_port= request.POST.get('dst_port')
            proto= request.POST.get('proto')
            duration= request.POST.get('duration')
            src_bytes= request.POST.get('src_bytes')
            dst_bytes= request.POST.get('dst_bytes')
            conn_state= request.POST.get('conn_state')
            missed_bytes= request.POST.get('missed_bytes')
            src_pkts= request.POST.get('src_pkts')
            src_ip_bytes= request.POST.get('src_ip_bytes')
            dst_pkts= request.POST.get('dst_pkts')
            dst_ip_bytes= request.POST.get('dst_ip_bytes')
            dns_qclass= request.POST.get('dns_qclass')
            dns_qtype= request.POST.get('dns_qtype')
            dns_rcode= request.POST.get('dns_rcode')
            http_request_body_len= request.POST.get('http_request_body_len')
            http_response_body_len= request.POST.get('http_response_body_len')
            http_status_code= request.POST.get('http_status_code')
        
        
        

        datas = pd.read_csv('ddos_dataset_sample.csv')
        # Encode categorical features
        label_encoders = {}
        for column in ['src_ip', 'dst_ip', 'proto', 'conn_state', 'type']:
            le = LabelEncoder()
            datas[column] = le.fit_transform(datas[column])
            label_encoders[column] = le

        # Split data into features and target
        X1 = datas.drop(columns=['type'])
        y1 = datas['type']

        # Standardize numerical features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X1)

        # Split into training and test sets
        X_train1, X_test1, y_train1, y_test1 = train_test_split(X_scaled, y1, test_size=0.2, random_state=42)

        # Train a Gradient Boosting model
        model = GradientBoostingClassifier(random_state=42)
        model.fit(X_train1, y_train1)
        sample_input = [
        timestamp, src_ip, src_port, dst_ip, dst_port, proto, duration, src_bytes, dst_bytes, 
        conn_state, missed_bytes, src_pkts, src_ip_bytes, dst_pkts, dst_ip_bytes, dns_qclass, 
        dns_qtype, dns_rcode, http_request_body_len, http_response_body_len, http_status_code
    ]
         # Encode categorical fields
        sample_input[1] = label_encoders['src_ip'].transform([sample_input[1]])[0]
        sample_input[3] = label_encoders['dst_ip'].transform([sample_input[3]])[0]
        sample_input[5] = label_encoders['proto'].transform([sample_input[5]])[0]
        sample_input[9] = label_encoders['conn_state'].transform([sample_input[9]])[0]
        
        # Scale numerical fields
        sample_input_scaled = scaler.transform([sample_input])
        
        # Predict the result
        prediction = model.predict(sample_input_scaled)
        # Decode the prediction back to the original label
        result = label_encoders['type'].inverse_transform(prediction)[0]
        print(result)

        Advanced_Intrusion_type_prediction.objects.create(
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        duration=duration,
        src_bytes=src_bytes,
        dst_bytes=dst_bytes,
        conn_state=conn_state,
        missed_bytes=missed_bytes,
        src_pkts=src_pkts,
        src_ip_bytes=src_ip_bytes,
        dst_pkts=dst_pkts,
        dst_ip_bytes=dst_ip_bytes,
        dns_qclass=dns_qclass,
        dns_qtype=dns_qtype,
        dns_rcode=dns_rcode,
        http_request_body_len=http_request_body_len,
        http_response_body_len=http_response_body_len,
        http_status_code=http_status_code,
        Prediction=result)

        return render(request, 'RUser/Predict_Advanced_Intrusion_Type.html',{'objs': result})
    return render(request, 'RUser/Predict_Advanced_Intrusion_Type.html')





from django.db.models import  Count, Avg
from django.shortcuts import render, redirect
from django.db.models import Count
from django.db.models import Q
import datetime
import xlwt
from django.http import HttpResponse


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

# Create your views here.
from Remote_User.models import ClientRegister_Model,Advanced_Intrusion_type_prediction,detection_ratio,detection_accuracy


def serviceproviderlogin(request):
    if request.method  == "POST":
        admin = request.POST.get('username')
        password = request.POST.get('password')
        if admin == "Admin" and password =="Admin":
            detection_accuracy.objects.all().delete()
            return redirect('View_Remote_Users')

    return render(request,'SProvider/serviceproviderlogin.html')

def View_Predicted_Advanced_Intrusion_Type_Ratio(request):
    detection_ratio.objects.all().delete()
    ratio = ""
    kword = 'ddos Attack'
    print(kword)
    obj = Advanced_Intrusion_type_prediction.objects.all().filter(Q(Prediction=kword))
    obj1 = Advanced_Intrusion_type_prediction.objects.all()
    count = obj.count();
    count1 = obj1.count();
    ratio = (count / count1) * 100
    if ratio != 0:
        detection_ratio.objects.create(names=kword, ratio=ratio)

    ratio12 = ""
    kword12 = 'Normal'
    print(kword12)
    obj12 = Advanced_Intrusion_type_prediction.objects.all().filter(Q(Prediction=kword12))
    obj112 = Advanced_Intrusion_type_prediction.objects.all()
    count12 = obj12.count();
    count112 = obj112.count();
    ratio12 = (count12 / count112) * 100
    if ratio12 != 0:
        detection_ratio.objects.create(names=kword12, ratio=ratio12)

    obj = detection_ratio.objects.all()
    return render(request, 'SProvider/View_Predicted_Advanced_Intrusion_Type_Ratio.html', {'objs': obj})

def View_Remote_Users(request):
    obj=ClientRegister_Model.objects.all()
    return render(request,'SProvider/View_Remote_Users.html',{'objects':obj})

def charts(request,chart_type):
    chart1 = detection_ratio.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts.html", {'form':chart1, 'chart_type':chart_type})

def charts1(request,chart_type):
    chart1 = detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts1.html", {'form':chart1, 'chart_type':chart_type})

def View_Predicted_Advanced_Intrusion_Type_Details(request):
    obj =Advanced_Intrusion_type_prediction.objects.all()
    return render(request, 'SProvider/View_Predicted_Advanced_Intrusion_Type_Details.html', {'list_objects': obj})

def likeschart(request,like_chart):
    charts =detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/likeschart.html", {'form':charts, 'like_chart':like_chart})


def Download_Predicted_DataSets(request):

    response = HttpResponse(content_type='application/ms-excel')
    # decide file name
    response['Content-Disposition'] = 'attachment; filename="Predicted_Datasets.xls"'
    # creating workbook
    wb = xlwt.Workbook(encoding='utf-8')
    # adding sheet
    ws = wb.add_sheet("sheet1")
    # Sheet header, first row
    row_num = 0
    font_style = xlwt.XFStyle()
    # headers are bold
    font_style.font.bold = True
    # writer = csv.writer(response)
    obj = Advanced_Intrusion_type_prediction.objects.all()
    data = obj  # dummy method to fetch data.
    for my_row in data:
        row_num = row_num + 1

        ws.write(row_num, 0, my_row.timestamp, font_style)
        ws.write(row_num, 1, my_row.src_ip, font_style)
        ws.write(row_num, 2, my_row.src_port, font_style)
        ws.write(row_num, 3, my_row.dst_ip, font_style)
        ws.write(row_num, 4, my_row.dst_port, font_style)
        ws.write(row_num, 5, my_row.proto, font_style)
        ws.write(row_num, 6, my_row.duration, font_style)
        ws.write(row_num, 7, my_row.src_bytes, font_style)
        ws.write(row_num, 8, my_row.dst_bytes, font_style)
        ws.write(row_num, 9, my_row.conn_state, font_style)
        ws.write(row_num, 10, my_row.missed_bytes, font_style)
        ws.write(row_num, 11, my_row.src_pkts, font_style)
        ws.write(row_num, 12, my_row.src_ip_bytes, font_style)
        ws.write(row_num, 13, my_row.dst_pkts, font_style)
        ws.write(row_num, 14, my_row.dst_ip_bytes, font_style)
        ws.write(row_num, 15, my_row.dns_qclass, font_style)
        ws.write(row_num, 11, my_row.dns_qtype, font_style)
        ws.write(row_num, 12, my_row.dns_rcode, font_style)
        ws.write(row_num, 13, my_row.http_request_body_len, font_style)
        ws.write(row_num, 14, my_row.http_response_body_len, font_style)
        ws.write(row_num, 15, my_row.http_status_code, font_style)
        ws.write(row_num, 16, my_row.Prediction, font_style)

    wb.save(response)
    return response

def train_model(request):
    detection_accuracy.objects.all().delete()

    data = pd.read_csv('ddos_dataset_sample.csv')
    models = []
        # Data Preprocessing
        # Encode target and categorical features, and scale the data
    le = LabelEncoder()
    data['type'] = le.fit_transform(data['type'])  # Encode target
    categorical_columns = ['src_ip', 'dst_ip', 'proto', 'conn_state']
    data[categorical_columns] = data[categorical_columns].apply(le.fit_transform)
    X = data.drop(columns=['type'])
    y = data['type']

        # Scale numerical features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

        # Split data
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    print("ExtraTreesClassifier")
       
    etc = ExtraTreesClassifier(random_state=42)
    etc.fit(X_train, y_train)
    knpredict = etc.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, knpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, knpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, knpredict))
    detection_accuracy.objects.create(names="ExtraTreesClassifier", ratio=accuracy_score(y_test, knpredict) * 100)

    print("GradientBoostingClassifier")
    gbc = GradientBoostingClassifier()
    gbc.fit(X_train, y_train)
    dtcpredict = gbc.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, dtcpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, dtcpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, dtcpredict))
    detection_accuracy.objects.create(names="GradientBoostingClassifier", ratio=accuracy_score(y_test, dtcpredict) * 100)

    print("MLPClassifier")
    from sklearn.neural_network import MLPClassifier
    mlpc = MLPClassifier(random_state=42, max_iter=300).fit(X_train, y_train)
    y_pred = mlpc.predict(X_test)
    testscore_mlpc = accuracy_score(y_test, y_pred)
    accuracy_score(y_test, y_pred)
    print(accuracy_score(y_test, y_pred))
    print(accuracy_score(y_test, y_pred) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, y_pred))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, y_pred))
    models.append(('MLPClassifier', mlpc))
    detection_accuracy.objects.create(names="MLPClassifier", ratio=accuracy_score(y_test, y_pred) * 100)

    print("DNN")

        # --- Deep Learning Models ---
        # Prepare labels for Deep Learning Models
    y_train_cat = to_categorical(y_train)
    y_test_cat = to_categorical(y_test)

        # DNN Model
    dnn = Sequential([
        Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
        Dropout(0.5),
        Dense(64, activation='relu'),
        Dense(len(np.unique(y)), activation='softmax')
    ])
    dnn.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    dnn.fit(X_train, y_train_cat, epochs=10, batch_size=64, validation_split=0.1)
    y_pred_dnn = np.argmax(dnn.predict(X_test), axis=1)
    y_proba_dnn = dnn.predict(X_test)
    DNNacc = accuracy_score(y_test, y_pred_dnn) * 100
    print(DNNacc)
    print(confusion_matrix(y_test, y_pred_dnn))
    print(classification_report(y_test, y_pred_dnn))
    models.append(('DNN', dnn))
    detection_accuracy.objects.create(names="DNN", ratio=DNNacc)

    # CNN Model (requires reshaping input for Conv1D)
    X_train_cnn = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
    X_test_cnn = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
    cnn = Sequential([
        Conv1D(32, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], 1)),
        MaxPooling1D(pool_size=2),
        Flatten(),
        Dense(64, activation='relu'),
        Dense(len(np.unique(y)), activation='softmax')
    ])
    cnn.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    cnn.fit(X_train_cnn, y_train_cat, epochs=10, batch_size=64, validation_split=0.1)
    y_pred_cnn = np.argmax(cnn.predict(X_test_cnn), axis=1)
    svm_acc = accuracy_score(y_test, y_pred_cnn) * 100
    print(svm_acc)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, y_pred_cnn))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, y_pred_cnn))
    detection_accuracy.objects.create(names="CNN", ratio=accuracy_score(y_test, y_pred) * 100)

     # ANN Model
    ann = Sequential([
        Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
        Dropout(0.5),
        Dense(64, activation='relu'),
        Dropout(0.5),
        Dense(32, activation='relu'),
        Dense(len(np.unique(y)), activation='softmax')
    ])
    ann.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    ann.fit(X_train, y_train_cat, epochs=10, batch_size=64, validation_split=0.1)
    y_pred_ann = np.argmax(ann.predict(X_test), axis=1)
    y_proba_ann = ann.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, y_pred_ann) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, y_pred_ann))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, y_pred_ann))
    models.append(('ANN', ann))
    detection_accuracy.objects.create(names="ANN",
                                      ratio=accuracy_score(y_test, y_pred_ann) * 100)

    csv_format = 'Results.csv'
    data.to_csv(csv_format, index=False)
    data.to_markdown

    obj = detection_accuracy.objects.all()
    return render(request,'SProvider/train_model.html', {'objs': obj})
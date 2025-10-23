from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    gender= models.CharField(max_length=30)
    address= models.CharField(max_length=30)


class Advanced_Intrusion_type_prediction(models.Model):

    timestamp= models.CharField(max_length=300)
    src_ip= models.CharField(max_length=300)
    src_port= models.CharField(max_length=300)
    dst_ip= models.CharField(max_length=300)
    dst_port= models.CharField(max_length=300)
    proto= models.CharField(max_length=300)
    duration= models.CharField(max_length=300)
    src_bytes= models.CharField(max_length=300)
    dst_bytes= models.CharField(max_length=300)
    conn_state= models.CharField(max_length=300)
    missed_bytes= models.CharField(max_length=300)
    src_pkts= models.CharField(max_length=300)
    src_ip_bytes= models.CharField(max_length=300)
    dst_pkts= models.CharField(max_length=300)
    dst_ip_bytes= models.CharField(max_length=300)
    dns_qclass= models.CharField(max_length=300)
    dns_qtype= models.CharField(max_length=300)
    dns_rcode= models.CharField(max_length=300)
    http_request_body_len= models.CharField(max_length=300)
    http_response_body_len= models.CharField(max_length=300)
    http_status_code= models.CharField(max_length=300)
    Prediction= models.CharField(max_length=300)


class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)




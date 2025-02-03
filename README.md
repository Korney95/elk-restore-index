### дампит mapping и настройки index в s3 
exaple usage:

```sh
pip install elasticsearch==7.17.0 boto3 requests_aws4auth
```
dump: 
```yaml
export INDICES="*"
export ES_URL="http://localhost:9200"
export S3_ACCESS_KEY="admin"
export S3_SECRET_KEY="admin"
export S3_BUCKET="backup"
export S3_PATH="elk/test"
export S3_ENDPOINT_URL="http://minio:9000"
```

```sh 
python3 es.py dump
```


restore:
```yaml
export INDICES="index1 index2"
export ES_URL="http://localhost:9200"
export S3_ACCESS_KEY="admin"
export S3_SECRET_KEY="admin"
export S3_BUCKET="backup"
export S3_PATH="elk/test"
export S3_ENDPOINT_URL="http://minio:9000"
```
```sh 
python3 es.py restore
```


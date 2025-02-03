FROM python:3.10.16-bullseye
WORKDIR /app
RUN pip install elasticsearch==7.17.0 boto3 requests_aws4auth
COPY . ./
CMD python3 /app/es.py dump

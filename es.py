#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import traceback

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# --------------------------- ПАРАМЕТРЫ И ТАЙМАУТЫ ----------------------------
ES_REQUEST_TIMEOUT = int(os.getenv("ES_REQUEST_TIMEOUT", "30"))
ES_MAX_RETRIES = int(os.getenv("ES_MAX_RETRIES", "3"))
ES_RETRY_ON_TIMEOUT = (os.getenv("ES_RETRY_ON_TIMEOUT", "true").lower() == "true")

S3_CONNECT_TIMEOUT = int(os.getenv("S3_CONNECT_TIMEOUT", "10"))
S3_READ_TIMEOUT = int(os.getenv("S3_READ_TIMEOUT", "60"))
S3_MAX_ATTEMPTS = int(os.getenv("S3_MAX_ATTEMPTS", "3"))

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# --------------------------- НАСТРОЙКА ЛОГИРОВАНИЯ ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --------------------------- УТИЛИТЫ ДЛЯ РАБОТЫ С ES --------------------------
def get_elasticsearch_client(es_url, aws_access_key=None, aws_secret_key=None):
    use_awsauth = ('amazonaws.com' in es_url) and aws_access_key and aws_secret_key

    if use_awsauth:
        awsauth = AWS4Auth(aws_access_key, aws_secret_key, AWS_REGION, 'es')
        client = Elasticsearch(
            hosts=[es_url],
            http_auth=awsauth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
            timeout=ES_REQUEST_TIMEOUT,
            max_retries=ES_MAX_RETRIES,
            retry_on_timeout=ES_RETRY_ON_TIMEOUT
        )
    else:
        client = Elasticsearch(
            [es_url],
            verify_certs=False,
            timeout=ES_REQUEST_TIMEOUT,
            max_retries=ES_MAX_RETRIES,
            retry_on_timeout=ES_RETRY_ON_TIMEOUT
        )
    return client

def fetch_index_config(es_client, index_name):
    settings = es_client.indices.get_settings(index=index_name)
    mappings = es_client.indices.get_mapping(index=index_name)
    return {
        "settings": settings[index_name]['settings'],
        "mappings": mappings[index_name]['mappings']
    }

def create_index_from_config(es_client, index_name, config, force_delete=False):
    if es_client.indices.exists(index=index_name):
        if force_delete:
            logger.info(f"Deleting existing index [{index_name}]")
            es_client.indices.delete(index=index_name)
        else:
            logger.warning(f"Skipping existing index [{index_name}] (use --force to overwrite)")
            return

    config['settings']['index'].pop('uuid', None)
    config['settings']['index'].pop('provided_name', None)
    config['settings']['index'].pop('creation_date', None)
    config['settings']['index'].pop('version', None)

    es_client.indices.create(index=index_name, body={
        "settings": config["settings"],
        "mappings": config["mappings"]
    })
    logger.info(f"Index [{index_name}] created successfully")

# --------------------------- УТИЛИТЫ ДЛЯ РАБОТЫ С S3 --------------------------
def get_s3_client(aws_access_key, aws_secret_key, endpoint_url=None):
    boto_config = Config(
        connect_timeout=S3_CONNECT_TIMEOUT,
        read_timeout=S3_READ_TIMEOUT,
        retries={'max_attempts': S3_MAX_ATTEMPTS, 'mode': 'standard'}
    )

    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key
    )

    return session.client(
        's3',
        endpoint_url=endpoint_url,
        region_name=AWS_REGION,
        config=boto_config
    )

def upload_json_to_s3(s3_client, bucket, path, filename, data):
    key = f"{path.rstrip('/')}/{filename}" if path else filename
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data, ensure_ascii=False, indent=2),
        ContentType='application/json'
    )
    logger.info(f"Uploaded {filename} to s3://{bucket}/{key}")

def download_json_from_s3(s3_client, bucket, path, filename):
    key = f"{path.rstrip('/')}/{filename}" if path else filename
    response = s3_client.get_object(Bucket=bucket, Key=key)
    return json.loads(response['Body'].read().decode('utf-8'))

# --------------------------- НОВЫЕ ФУНКЦИИ ДЛЯ ВСЕХ ИНДЕКСОВ ------------------
def get_all_es_indices(es_client):
    try:
        indices = es_client.indices.get(index='*').keys()
        return [idx for idx in indices if not idx.startswith('.')]
    except Exception as e:
        logger.error(f"Error listing indices: {str(e)}")
        raise

def list_s3_index_files(s3_client, bucket, prefix):
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        results = paginator.paginate(Bucket=bucket, Prefix=prefix)
        return [
            item['Key'].split('/')[-1][len('index_'):-len('.json')]
            for page in results
            for item in page.get('Contents', [])
            if item['Key'].endswith('.json') and 'index_' in item['Key']
        ]
    except Exception as e:
        logger.error(f"Error listing S3 objects: {str(e)}")
        raise

# --------------------------- ОСНОВНЫЕ ФУНКЦИИ --------------------------------
def dump_indices(es_url, s3_bucket, s3_path, indices, aws_access_key, aws_secret_key, s3_endpoint=None):
    es_client = get_elasticsearch_client(es_url, aws_access_key, aws_secret_key)
    s3_client = get_s3_client(aws_access_key, aws_secret_key, s3_endpoint)

    for index in indices:
        try:
            config = fetch_index_config(es_client, index)
            upload_json_to_s3(
                s3_client,
                s3_bucket,
                s3_path,
                f"index_{index}.json",
                config
            )
        except Exception as e:
            logger.error(f"Failed to dump index {index}: {str(e)}")
            traceback.print_exc()

def restore_indices(es_url, s3_bucket, s3_path, indices, aws_access_key, aws_secret_key, force=False, s3_endpoint=None):
    es_client = get_elasticsearch_client(es_url, aws_access_key, aws_secret_key)
    s3_client = get_s3_client(aws_access_key, aws_secret_key, s3_endpoint)

    for index in indices:
        try:
            config = download_json_from_s3(
                s3_client,
                s3_bucket,
                s3_path,
                f"index_{index}.json"
            )
            create_index_from_config(es_client, index, config, force)
        except Exception as e:
            logger.error(f"Failed to restore index {index}: {str(e)}")
            traceback.print_exc()

# --------------------------- ТОЧКА ВХОДА -------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python es_backup.py [dump|restore] [--force]")
        sys.exit(1)

    command = sys.argv[1].lower()
    force = '--force' in sys.argv[2:] and command == "restore"

    # Read environment variables
    es_url = os.getenv("ES_URL")
    s3_access = os.getenv("S3_ACCESS_KEY")
    s3_secret = os.getenv("S3_SECRET_KEY")
    s3_bucket = os.getenv("S3_BUCKET")
    s3_path = os.getenv("S3_PATH", "")
    s3_endpoint = os.getenv("S3_ENDPOINT_URL")
    indices_env = os.getenv("INDICES", "")

    # Validation
    if not all([es_url, s3_access, s3_secret, s3_bucket]):
        logger.error("Missing required environment variables")
        sys.exit(1)

    # Process indices
    if '*' in indices_env:
        if command == "dump":
            es_client = get_elasticsearch_client(es_url, s3_access, s3_secret)
            indices = get_all_es_indices(es_client)
            logger.info(f"Found {len(indices)} indices to dump")
        elif command == "restore":
            s3_client = get_s3_client(s3_access, s3_secret, s3_endpoint)
            prefix = f"{s3_path}/" if s3_path else ""
            indices = list_s3_index_files(s3_client, s3_bucket, f"{prefix}index_")
            logger.info(f"Found {len(indices)} indices to restore")
    else:
        indices = [idx.strip() for idx in indices_env.split() if idx.strip()]

    if not indices:
        logger.error("No indices specified or found")
        sys.exit(1)

    # Execute command
    if command == "dump":
        dump_indices(es_url, s3_bucket, s3_path, indices, s3_access, s3_secret, s3_endpoint)
    elif command == "restore":
        restore_indices(es_url, s3_bucket, s3_path, indices, s3_access, s3_secret, force, s3_endpoint)
    else:
        logger.error(f"Invalid command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()

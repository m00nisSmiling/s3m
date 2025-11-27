# s3m
Monitor and cover AWS S3 Infra from malicious file upload vulnerabilities 

## OS support
> Linux

## Requirements
This automation tool used aws cli for monitoring. So, you need to install aws-cli first :
> Install aws-cli in your computer [ https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html ]

You need to configure AWS account to monitor your s3 infra:
> $ aws configure

Then install other requirements using pip :
> $ pip install requests termcolor --break-system-packages

## Installation Steps
#### $ git clone https://github.com/m00nisSmiling/s3m.git
#### $ cd s3m
#### $ chmod +x ./s3m.py
#### $ ./s3m.py -get bucket               # get the list of buckets
#### $ ./s3m.py -get log                  # log every files from s3 buckets
#### $ ./s3m.py -get path                 # get every file paths from s3 buckets
#### $ ./s3m.py -scan                     # scan s3 buckets using names and extensions from ./extensions.txt to look for malicious files
#### $ ./s3m.py -aggressive               # scan the file contents from s3 buckets using the checklist file ./checklist.txt
#### $ ./s3m.py -url [url]                # check the file contents and modified date of provided url
#### $ ./s3m.py -del s3://[bucket]/path   # delete the provided file from bucket
#### $ ./s3m.py -check [bucket_name]      # check logs for provided bucket

## Screenshots
<img width="2560" height="1440" alt="New Project 8  2173FE0" src="https://github.com/user-attachments/assets/bc3307a4-b471-4c98-961c-6f8ff8e49695" />

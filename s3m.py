#!/usr/bin/python3
import os
import json
from termcolor import colored
import sys
import requests

def options():
    print(colored("\n [!] Before other operations, you need run this command to get bucket list -> ./s3m.py -get bucket","blue"))
    print(colored("""
 -get bucket           =     Get bucket list from aws account
 -get log              =     Get log from all infra of s3
 -get path             =     Get file paths from all of s3 buckets to test
 
 -scan                 =     Find malicious files in s3 buckets using file extensions & names
 -aggresive            =     Find malicious files by using payloads from checklist.txt
 -url [url]            =     Check the contents of file
 -del s3://bucket/path =     To delete provided file from the bucket
 
 -check [bucket_name]  =     Check the log of specified s3 bucket""","white"))

def help():
    options() 

def delete(b):
    if b[0:4]=="s3://":
        os.system(f"aws s3 rm {b}")
    else:
        help()
        
def nodate_out(): 
    with open("./buckets.txt") as f:
        buckets = [x.strip() for x in f if x.strip()]

    with open("./extensions.txt") as f:
        exts = [x.strip() for x in f if x.strip()]
    for bucket in buckets:
        #print(colored(f"| FETCHING |------>","blue"),colored(f" {bucket}", "magenta"))
        stream = os.popen(
            f"aws s3api list-objects-v2 --bucket {bucket} --output json"
        )
        data = json.loads(stream.read())
        output_path = f"./output/{bucket}"
        with open(output_path, "w") as out:
            if "Contents" in data:
                for obj in data["Contents"]:
                    key = obj["Key"]
                    out.write(key + "\n")

        print(colored("[<-]","magenta"), colored(output_path, "blue"))

def buckets_log(x):
    out_path = f"./output/1.with_date/{x}"
    if not os.path.isfile(out_path):
        print(colored(f" [!] Run this to retrieve the logs from s3 infra -> $ ./s3m.py -get log","red"))
    else:
        filei = open(out_path,"r")
        print(colored(f"-> Log For [ {x} ]\n","yellow"),colored(filei.read(),"blue"))
    
def get_s3_bucket_list():
    os.system('aws s3 ls | cut -d " " -f3 > ./buckets.txt')
    print(colored("[<-] ","magenta"),"GOT IT ! ....")
    
def date_out():
    file_i = open("./buckets.txt").read()
    file_s = file_i.splitlines()

    for i in file_s:
        os.system(f"aws s3 ls s3://{i}/ --recursive > ./output/1.with_date/{i} ")
        print(colored("[<-]","magenta"),colored(f"./output/1.with_date/{i}","blue"))

def validation():
    os.system("rm -r ./output/log")
    with open("./buckets.txt", "r") as fh:
        buckets = [line.strip() for line in fh if line.strip()]

    search_terms = []
    with open("./extensions.txt", "r") as fh:
        for line in fh:
            s = line.strip().lower()
            if not s:
                continue
            if s.startswith("."):
                search_terms.append(("ext", s))
            else:
                if s.isalnum():
                    search_terms.append(("ext", "." + s))
                else:
                    search_terms.append(("key", s))

    if not search_terms:
        print(colored("[!] No search terms found in extensions.txt", "red"))
        raise SystemExit(1)

    for bucket in buckets:
        print(colored(
            "--------------------\n|",
            "white"), colored(">", "red"), colored(bucket, "blue")
        )

        out_path = f"./output/{bucket}"
        if not os.path.isfile(out_path):
            print(colored(f"  [!] Run this to retrieve the file path from s3 infra -> $ ./s3m.py -get path", "red"))
            continue
       
        seen = set()
        
        with open(out_path, "r", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue

                parts = line.split()
                if not parts:
                    continue

                key = parts[-1]
                key_lower = key.lower()

                matched = False

                for item_type, term in search_terms:
                    if item_type == "ext":
                        if key_lower.endswith(term):
                            matched = True
                            break
                    else:
                        if term in key_lower:
                            matched = True
                            break
                
                if matched and line not in seen:
                    uvar = f"http://{bucket}.s3.amazonaws.com/{line}"
                    fileo1 = open("./output/log","a")
                    fileo1.write(uvar+"\n")
                    print(colored(f"{uvar}","green"))
                    seen.add(line)

def contype(x):
    try:
        getfile = requests.get(x)
    except requests.exceptions.ConnectionError:
        help()
        pass
    except requests.exceptions.MissingSchema:
        help()
        pass
    else:
        print(colored("-------------------\n","white"),colored("Content-Type       > ","blue"),colored(getfile.headers.get('Content-Type'),"green"))
        print(colored(" Last-Modified-Date > ","magenta"),colored(getfile.headers.get('Last-Modified'),"green"))
        print(colored("-------------------","white"))
        print(colored(getfile.text,"white"))

def aggre():
    fileo1 = open("./output/log").read()
    files1 = fileo1.splitlines()
    fileo2 = open("./checklist.txt").read()
    files2 = fileo2.splitlines()
    for i in files1:
        p1 = requests.get(i)
        response = p1.text
        for q in files2:
            if q in response:
                print(colored("[!]","red"),f"{i} ",colored("| Found -> ","blue"),"[",colored(f"{q}","red"),"]")

try:
    option = sys.argv[1]
except IndexError:
    help()
else:
    try:
        argument = sys.argv[2]
        if option == "-get":
            if argument == "log":
                date_out()
            elif argument == "path":
                nodate_out()
            elif argument == "bucket":
                get_s3_bucket_list()
            else:
                help()
        elif option == "-check":
            buckets_log(argument)
        elif option == "-url":
            contype(argument)
        elif option == "-del":
            delete(argument)
        else:
            help() 
    except IndexError:
        if option == "-scan":
            validation()
        elif option == "-aggressive":
            aggre()
        else:
            help()
#def mainloop():
#    print(colored("--------------------","white"))
#    inp1 = input(colored("</> ","red"))
#    if inp1 == "1":
#        date_out()
#    elif inp1 == "2":
#        nodate_out()
#    elif inp1 == "3":
#        validation()
#    elif inp1 == "delete":
#        delete()
#    elif inp1 == "exit":
#        sys.exit()
#    else:
#        contype(inp1)

#while True:        
#    mainloop()

FROM ubuntu:latest

RUN apt-get update && apt -y upgrade && apt-get install -y python3 python3-pip

COPY requirements.txt requirements.txt
COPY ./server.py /srv/run_server.py

RUN pip3 install -r requirements.txt --break-system-package

EXPOSE 65432

CMD ["python3","-u","/srv/run_server.py"]

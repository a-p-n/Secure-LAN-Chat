FROM ubuntu:latest

RUN apt-get update && apt -y upgrade && apt-get install -y python3 python3-pip

USER user

COPY requirements.txt requirements.txt
COPY ./server.py /srv/server.py

RUN pip3 install -r requirements.txt --break-system-package

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/srv"]
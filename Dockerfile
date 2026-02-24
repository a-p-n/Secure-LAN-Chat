FROM ubuntu:latest

RUN apt-get update && apt -y upgrade && apt-get install -y python3 python3-pip

RUN useradd -m user

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt --break-system-package

WORKDIR /srv
COPY ./server.py /srv/server.py

RUN chown -R user:user /srv

USER user

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/srv"]
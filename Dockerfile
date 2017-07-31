FROM python:alpine

WORKDIR /usr/src/app

RUN pip install watchdog

COPY acme-dump.py acme-dump.py

CMD [ "python", "./acme-dump.py", "/acme", "acme.json", "/acme/certs" ]

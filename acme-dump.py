#!/usr/bin/env python
import argparse
import base64
import json
import logging
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def main():
    parser = argparse.ArgumentParser(
        description="Dump all certificates out of Traefik's acme.json file")
    parser.add_argument('acme_dir', help='path to directory containing the acme.json file')
    parser.add_argument('acme_json', help='the acme.json file name')
    parser.add_argument('dest_dir',
                        help='path to the directory to store the certificate')

    args = parser.parse_args()

    if not os.path.exists(args.dest_dir):
        os.makedirs(args.dest_dir, 0O755)

    dump(os.path.join(args.acme_dir, args.acme_json), args.dest_dir)

    event_handler = AcmeEventHandler(args.acme_json, args.dest_dir)
    observer = Observer()
    observer.schedule(event_handler, args.acme_dir)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except:
        observer.stop()
    observer.join()


def read_cert(storage_dir, filename):
    cert_path = os.path.join(storage_dir, filename)
    if os.path.exists(cert_path):
        with open(cert_path) as cert_file:
            return cert_file.read()
    return None


def write_cert(storage_dir, domain, cert_content):
    cert_path = os.path.join(storage_dir, '%s.pem' % (domain,))
    with open(cert_path, 'wb') as cert_file:
        cert_file.write(cert_content)
    os.chmod(cert_path, 0o600)


def read_certs(acme_json_path):
    with open(acme_json_path) as acme_json_file:
        acme_json = json.load(acme_json_file)

    certs_json = acme_json['DomainsCertificate']['Certs']
    certs = {}
    for cert in certs_json:
        domain = cert['Domains']['Main']
        domain_cert = cert['Certificate']
        # Only get the first cert (should be the most recent)
        if domain not in certs:
            certs[domain] = to_pem_data(domain_cert)

    return certs


def to_pem_data(json_cert):
    return b''.join((base64.b64decode(json_cert['Certificate']),
                     base64.b64decode(json_cert['PrivateKey'])))


def dump(acme_json, dest_dir):
    certs = read_certs(acme_json)
    logging.info('Found certs for %d domains', len(certs))
    for domain, cert in certs.items():
        logging.info('Writing cert for domain %s', domain)
        write_cert(dest_dir, domain, cert)
    logging.info('Done')


class AcmeEventHandler(FileSystemEventHandler):
    """Logs all the events captured."""

    def __init__(self, acme_json, dest_dir):
        self._acme_json = acme_json
        self._dest_dir = dest_dir

    @property
    def acme_json(self):
        """acme_json file name."""
        return self._acme_json

    @property
    def dest_dir(self):
        """Destination directory where to dump certs."""
        return self._dest_dir

    def on_created(self, event):
        super(LoggingEventHandler, self).on_created(event)

        if os.path.basename(event.src_path) == self.acme_json:
            dump(event.src_path, self.dest_dir)

    def on_modified(self, event):
        super(LoggingEventHandler, self).on_modified(event)

        if os.path.basename(event.src_path) == self.acme_json:
            dump(event.src_path, self.dest_dir)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    main()


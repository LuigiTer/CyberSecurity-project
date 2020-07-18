#! /bin/python3

import socket
import ssl

COMMON_NAME = "www.serverDP3T.com"
FILENAME = "./to_server.pem"
SERVER_BACKEND_CERT_PATH = "../intermediateCA/certs/intermediateCA-rootCA-chain.cert.pem"
HOST = "127.0.0.1"
PORT = 8443
MAX_MESSAGE_SIZE = 512

COUNTRY_NAME = "IT"
# COMMON_NAME = "www.serverDP3T.com"
ORGANIZATION_NAME = "Ministero della Salute"

COUNTRY_NAME_ISSUER = "IT"
COMMON_NAME_ISSUER = "min.gov.salute"
ORGANIZATION_NAME_ISSUER = "Ministero della Salute"


def verify_server(cert):
    """
    Verify that the certificate corresponds to the one issued by the authorities.
    :param cert: the certficate to be verified
    :returns: None
    :raise Exception: an exception is raised if the certificate is not valid
    """
    if not cert:
        raise Exception('')

    if ('commonName', COMMON_NAME) not in cert['subject'][3] \
            or ('countryName', COUNTRY_NAME) not in cert['subject'][0] \
            or ('organizationName', ORGANIZATION_NAME) not in cert['subject'][2]:
        raise Exception("Certificate of intermediateCA is not valid")

    if ('commonName', COMMON_NAME_ISSUER) not in cert['issuer'][4] \
            or ('countryName', COUNTRY_NAME_ISSUER) not in cert['issuer'][0] \
            or ('organizationName', ORGANIZATION_NAME_ISSUER) not in cert['issuer'][3]:
        raise Exception("Certificate of rootCA is not valid")


def send_data_to_server(data):
    # opening a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(SERVER_BACKEND_CERT_PATH)
    secure_sock = context.wrap_socket(sock, server_hostname=HOST, server_side=False)

    # get the server certificate and verify it
    cert = secure_sock.getpeercert()
    try:
        verify_server(cert)
    except Exception as e:
        print(str(e))
        raise SystemExit

    # reading and printing the welcome message from the server
    received_data = secure_sock.read(MAX_MESSAGE_SIZE)
    print(received_data)

    # reading the data to send (in the real scenario, this file comes from the bluetooth comunication)
    secure_sock.write(data)

    # reading and printing the response from the server
    received_data = secure_sock.read(MAX_MESSAGE_SIZE)
    print(received_data)

    # closing the connection
    secure_sock.close()
    sock.close()

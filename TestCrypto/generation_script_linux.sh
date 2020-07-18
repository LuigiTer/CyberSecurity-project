#! /bin/bash

echo "****** Cleaning the previously generated files... "
rm -rf *.pem
rm -rf rootCA
rm -rf intermediateCA
rm -rf receiver/*.pem
rm -rf receiver/*.txt
rm -rf sender/infected
mkdir sender/infected
rm -rf sender/not_infected
mkdir sender/not_infected

echo "****** Setting up the folder structure for the rootCA ******"
mkdir rootCA
mkdir rootCA/private
mkdir rootCA/certs
touch rootCA/index.txt
touch rootCA/index.txt.attr
echo 01 > rootCA/serial

echo "****** Installing libraries ******"
sleep 3
sudo apt install python3-pip
pip3 install pycryptodome

echo "****** Creating the private key for the rootCA ******"
openssl genrsa  -out rootCA/private/rootCAkey.pem 4096

echo "****** Making a request for the rootCA to selfsign its certificate ******"
openssl req -new -x509 -days 3650 -config config/opensslconfigRootCA.cnf -extensions v3_ca -key rootCA/private/rootCAkey.pem -out rootCA/certs/rootCAcert.pem -batch 

echo "****** Converting in pem ******"
openssl x509 -in rootCA/certs/rootCAcert.pem -out rootCA/certs/rootCAcert.pem -outform PEM

echo "****** Setting up the folder structure for the intermediateCA ******"
mkdir intermediateCA
mkdir intermediateCA/private
mkdir intermediateCA/certs
mkdir intermediateCA/csr
touch intermediateCA/index.txt
echo 01 > intermediateCA/serial

echo "****** Creating the private key for the intermediateCA ******"
openssl genrsa -out intermediateCA/private/intermediateCAkey.pem 4096

echo "****** Making a request to the rootCA to sign the intermediateCA certificate ******"
openssl req -new -sha256 -config config/opensslconfigServerBackend.cnf -key intermediateCA/private/intermediateCAkey.pem -out intermediateCA/csr/intermediateCA.csr.pem -batch

echo "****** Signing the intermediateCA certificate ******"
openssl ca -config config/opensslconfigRootCA.cnf -extensions v3_intermediate_ca -days 365 -notext -batch -in intermediateCA/csr/intermediateCA.csr.pem -out intermediateCA/certs/intermediateCAcert.pem

echo "****** Converting in pem ******"
openssl x509 -in intermediateCA/certs/intermediateCAcert.pem -out intermediateCA/certs/intermediateCAcert.pem -outform PEM

echo "****** Creating the certificates chain ******"
cat intermediateCA/certs/intermediateCAcert.pem rootCA/certs/rootCAcert.pem > intermediateCA/certs/intermediateCA-rootCA-chain.cert.pem

echo "****** Verifing the certificates chain ******"
openssl verify -CAfile rootCA/certs/rootCAcert.pem intermediateCA/certs/intermediateCAcert.pem

echo "****** Generating the broadcast key ******"
python3 generate_broadcast_key.py

echo "****** All done ******"
sleep 3

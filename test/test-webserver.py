#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import signal
import re
import subprocess
import sys
from json import JSONDecodeError
from pathlib import Path
import shutil
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
import logging
import json
import filetype


pki_is_persistent = True
rsa_keysize = 2048
pki_dir = "test-pki"
ca_password = "geheim"
server_keystore = {"ca": ""}
pid_file = "./test-webserver.py.pid"

config = {}

server_key_files = {
    "ca": f'{pki_dir}/ca.crt',
    "key": "./test-cert.key",
    "crt": "./test-cert.crt",
    "key-sign": "./test-cert-sign.key",
    "crt-sign": "./test-cert-sign.crt",
}


def sigterm_handler(_signo, _stack_frame):
    os.unlink(pid_file)
    sys.exit(0)


def pidfile():
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    f.close()


def openssl_cnf(filename, sans):
    """
    Creates openssl.cnf file with entries for Subject Alternative Names
    :param filename: path to which file will be written
    :param sans: Array of SANs or string with single SAN
    :return: Nothing
    """

    str_sans = ""
    if type(sans) is str:
        str_sans = sans
    else:
        for san in sans:
            if len(str_sans) > 0:
                str_sans = str_sans + "\n"
            str_sans = str_sans + san

    cnf = """\
#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
#

# Note that you can include other files from the main configuration
# file using the .include directive.
#.include filename

# This definition stops the following lines choking if HOME isn't
# defined.
HOME			= .

# Extra OBJECT IDENTIFIER info:
#oid_file		= $ENV::HOME/.oid
oid_section		= new_oids

# To use this configuration file with the "-extfile" option of the
# "openssl x509" utility, name here the section containing the
# X.509v3 extensions to use:
# extensions		=
# (Alternatively, use a configuration file that has only
# X.509v3 extensions in its main [= default] section.)

[ new_oids ]

# We can add new OIDs in here for use by 'ca', 'req' and 'ts'.
# Add a simple OID like this:
# testoid1=1.2.3.4
# Or use config file substitution like this:
# testoid2=${testoid1}.5.6

# Policies used by the TSA examples.
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

####################################################################
[ ca ]
default_ca	= CA_default		# The default ca section

####################################################################
[ CA_default ]

dir		= ./test-pki		# Where everything is kept
certs		= $dir/certs		# Where the issued certs are kept
crl_dir		= $dir/crl		# Where the issued crl are kept
database	= $dir/index.txt	# database index file.
unique_subject	= no			# Set to 'no' to allow creation of
                    # several certs with same subject.
new_certs_dir	= $dir/newcerts		# default place for new certs.

certificate	= $dir/cacert.pem 	# The CA certificate
serial		= $dir/serial 		# The current serial number
crlnumber	= $dir/crlnumber	# the current crl number
                    # must be commented out to leave a V1 CRL
crl		= $dir/crl.pem 		# The current CRL
private_key	= $dir/private/cakey.pem# The private key

x509_extensions	= usr_cert		# The extensions to add to the cert

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options

# Extension copying option: use with caution.
copy_extensions = none

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crlnumber must also be commented out to leave a V1 CRL.
# crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy		= policy_anything

# For the CA policy
[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

####################################################################
[ req ]
default_bits		= 2048
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extensions to add to the self signed cert

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options.
# default: PrintableString, T61String, BMPString.
# pkix	 : PrintableString, BMPString (PKIX recommendation before 2004)
# utf8only: only UTF8Strings (PKIX recommendation after 2004).
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
string_mask = utf8only

# req_extensions = v3_req # The extensions to add to a certificate request

subjectAltName = @alt_names

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= AU
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgits Pty Ltd

# we can do this but it is not needed normally :-)
#1.organizationName		= Second Organization Name (eg, company)
#1.organizationName_default	= World Wide Web Pty Ltd

organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64

# SET-ex3			= SET extension number 3

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

subjectAltName = @alt_names

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This is required for TSA certificates.
# extendedKeyUsage = critical,timeStamping

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]

%(str_sans)s

[ v3_ca ]

# Extensions for a typical CA

# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer

basicConstraints = critical,CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# keyUsage = cRLSign, keyCertSign

# Some might want this also
# nsCertType = sslCA, emailCA

# Include email address in subject alt name: another PKIX recommendation
# subjectAltName=email:copy
# Copy issuer details
# issuerAltName=issuer:copy

# DER hex encoding of an extension: beware experts only!
# obj=DER:02:03
# Where 'obj' is a standard or added object
# You can even override a supported extension:
# basicConstraints= critical, DER:30:03:01:01:FF

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
# These extensions should be added when creating a proxy certificate

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This really needs to be in place for it to be a proxy certificate.
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

####################################################################
[ tsa ]

default_tsa = tsa_config1	# the default TSA section

[ tsa_config1 ]

# These are used by the TSA reply generation only.
dir		= ./demoCA		# TSA root directory
serial		= $dir/tsaserial	# The current serial number (mandatory)
crypto_device	= builtin		# OpenSSL engine to use for signing
signer_cert	= $dir/tsacert.pem 	# The TSA signing certificate
                    # (optional)
certs		= $dir/cacert.pem	# Certificate chain to include in reply
                    # (optional)
signer_key	= $dir/private/tsakey.pem # The TSA private key (optional)
signer_digest  = sha256			# Signing digest to use. (Optional)
default_policy	= tsa_policy1		# Policy if request did not specify it
                    # (optional)
other_policies	= tsa_policy2, tsa_policy3	# acceptable policies (optional)
digests     = sha1, sha256, sha384, sha512  # Acceptable message digests (mandatory)
accuracy	= secs:1, millisecs:500, microsecs:100	# (optional)
clock_precision_digits  = 0	# number of digits after dot. (optional)
ordering		= yes	# Is ordering defined for timestamps?
                # (optional, default: no)
tsa_name		= yes	# Must the TSA name be included in the reply?
                # (optional, default: no)
ess_cert_id_chain	= no	# Must the ESS cert id chain be included?
                # (optional, default: no)
ess_cert_id_alg		= sha1	# algorithm to compute certificate
                # identifier (optional, default: sha1)
    """ % locals()
    with open(filename, "w") as f:
        f.write(cnf)
    f.close()


def get_temp_filename():
    return str(uuid.uuid4())


def exec_cmd(cmd):
    """
    Executes a shell command
    :param cmd: Array of command itself and its parameters
    :return: CompletedProcess object
    """
    print(' '.join(str(e) for e in cmd))
    try:
        res = subprocess.run(cmd, capture_output=True, check=True)
        print(res.stdout.decode("utf8"))
        return res
    except subprocess.CalledProcessError as err:
        logging.error(err.stderr)
        raise err


def create_CA(dn):
    """
    Creates a CA root certificate for internal PKI
    Used by create_pki()
    :param dn: Distinguished Name in form of /CN=.../O=... etc. as String
    :return: Nothing
    """
    cmd_genrsa = ["openssl",
                  "genrsa",
                  "-aes256",
                  "-out", f'{pki_dir}/ca.key',
                  "-passout", f'pass:{ca_password}',
                  f'{rsa_keysize}']
    cmd_req = ["openssl",
               "req",
               "-new",
               "-x509",
               "-days", "999999",
               "-sha256",
               "-key", f'{pki_dir}/ca.key',
               "-out", server_key_files["ca"],
               "-subj", f'{dn}',
               "-passin", f'pass:{ca_password}']
    cmds = [cmd_genrsa, cmd_req]
    for cmd in cmds:
        exec_cmd(cmd)


def create_pki():
    """
    Creates a PKI directory structure and CA root certificates
    Used by init_pki()
    :return: Nothing
    """
    os.mkdir(pki_dir)
    os.mkdir(f'{pki_dir}/newcerts')
    Path(f'{pki_dir}/index.txt').touch()
    with open(f'{pki_dir}/serial', 'w') as serial_file:
        serial_file.write('00000000')
    serial_file.close()
    create_CA('/CN=My cool CA/O=Honest Achmed/OU=Used Cars/C=EU')


def reset_pki():
    """
    Deletes PKI directory structure
    :return: Nothing
    """
    with open(f'{pki_dir}/serial', 'w') as serial_file:
        serial_file.write('00000000')
    serial_file.close()
    os.remove(f'{pki_dir}/*')


def init_pki():
    """
    Creates a simple OpenSSL based PKI
    :return: Nothing
    """
    global server_keystore

    if pki_is_persistent:
        if not Path(pki_dir).is_dir():
            create_pki()
        else:
            print(f'Do nothing, {pki_dir} already exists')
    else:
        if Path(pki_dir).is_dir():
            shutil.rmtree(pki_dir)
        create_pki()
    with open(server_key_files["ca"]) as crt:
        server_keystore["ca"] = crt.read()
    crt.close()


def convert_dn(dn):
    """
    Converts a DN in form "CN = ..., OU = ..." etc.
    to form "/CN=.../OU=..." etc. If entry form is
    already "/..." it does nothing and returns original DN string
    :param dn: DN string to convert
    :return: converted DN string
    """
    if re.match("^/.*", dn):
        return dn

    new_dn = ""
    attrs = dn.split(",")
    for attr in attrs:
        prm_tuple = attr.split("=")
        k = prm_tuple[0].strip()
        v = prm_tuple[1].strip()
        new_dn = new_dn + f'/{k}={v}'
    return new_dn


def sign_csr(csr, dn, sans, debug=False):
    """
    Signs PKCS#10 CSR and overwrites DN/SANs
    :param csr: PKCS#1ß request as PEM
    :param dn: DN which is set in certificate
    :param sans: Subject alternative names
    :param debug: If True, then temp files are not deleted
    :return: Certificate in PEM format
    """
    tmp_file = f'/tmp/{get_temp_filename()}'
    csr_filename = f'{tmp_file}.csr'
    crt_filename = f'{tmp_file}.crt'
    openssl_filename = f'{tmp_file}.cnf'
    with open(csr_filename, 'w') as csr_file:
        csr_file.write(csr)
    csr_file.close()

    openssl_cnf(openssl_filename, sans)

    cmd = [
        "openssl",
        "ca",
        "-config", f'{openssl_filename}',
        "-batch",
        "-subj", dn,
        "-keyfile", f'{pki_dir}/ca.key',
        "-cert", f'{pki_dir}/ca.crt',
        "-in", f'{csr_filename}',
        "-days", "735",
        "-out", f'{crt_filename}',
        "-notext",
        "-passin", f'pass:{ca_password}'
    ]
    read_data = ""
    try:
        exec_cmd(cmd)
        with open(crt_filename) as f:
            read_data = f.read()
        f.close()
        os.remove(crt_filename)
    except OSError as err:
        logging.error(f'Certificate signing failed: {err}')
    finally:
        if not debug:
            rm_filenames = [csr_filename, openssl_filename]
            for f in rm_filenames:
                os.remove(f)
    return read_data


def read_keypair(priv_key_file, public_key_file):
    """
    Reads keypair from files
    :param priv_key_file: PEM file with private key
    :param public_key_file: PEM file with public key
    :return: Keypair object
    """
    key_pair = {}
    with open(priv_key_file) as f:
        key_data = f.read()
    f.close()
    key_pair["key"] = key_data
    with open(public_key_file) as f:
        pub_data = f.read()
    f.close()
    key_pair["pub"] = pub_data
    for i in [priv_key_file, public_key_file]:
        os.remove(i)
    return key_pair


def create_csr(dn):
    """
    Creates a PKCS#10 Certificate Signing Request and RSA key
    :param dn: DN as string
    :return: Keypair
    """
    tmp_file = f'/tmp/{get_temp_filename()}'
    key_filename = f'{tmp_file}.key'
    csr_filename = f'{tmp_file}.csr'
    cmd = [
        "openssl",
        "req",
        "-subj", f'{dn}',
        "-newkey", f'rsa:{rsa_keysize}',
        "-keyout", f'{key_filename}',
        "-out", f'{csr_filename}',
        "-nodes"
    ]
    exec_cmd(cmd)
    return read_keypair(key_filename, csr_filename)


def create_csr_pss(dn):
    """
    Creates a PKCS#10 Certificate Signing Request and RSA-PSS key
    :param dn: DN as string
    :return: Keypair
    """
    tmp_file = f'/tmp/{get_temp_filename()}'
    key_filename = f'{tmp_file}.key'
    csr_filename = f'{tmp_file}.csr'

    cmd_genpkey = [
        "openssl",
        "genpkey",
        "-algorithm", "rsa-pss",
        "-pkeyopt", f'rsa_keygen_bits:{rsa_keysize}',
        "-pkeyopt", "rsa_keygen_pubexp:65537",
        "-out", f'{key_filename}'
    ]
    cmd_req = [
        "openssl",
        "req",
        "-new",
        "-subj", f'{dn}',
        "-key", f'{key_filename}',
        "-out", f'{csr_filename}'
    ]
    for cmd in [cmd_genpkey, cmd_req]:
        exec_cmd(cmd)

    return read_keypair(key_filename, csr_filename)


def create_server_certs_enc():
    """
    Creates server certificates for encryption for this tool and initializes local
    key store with private key and signed certificate.
    Used by create_server_certs()
    :return: Nothing
    """
    global server_keystore, config

    same_enc_sign_cert = config["config"]["same_enc_sign_cert"]
    if same_enc_sign_cert:
        dn = "/CN=server certificate RSA"
    else:
        dn = "/CN=server certificate encryption RSA"
    key_pair_rsa = create_csr(dn)
    server_keystore["key"] = key_pair_rsa["key"]
    san = [f'URI.1 = {uuid.uuid4().urn}']
    server_keystore["crt"] = sign_csr(key_pair_rsa["pub"], dn, san)


def create_server_certs_sign():
    """
    Creates server certificates for signing for this tool and initializes local
    key store with private key and signed certificate.
    Used only if different certificates for encryption and signing is set.
    Used by create_server_certs()
    :return: Nothing
    """
    global server_keystore

    dn_sign = "/CN=server certificate sign RSA-PSS"
    key_pair_rsa_sign = create_csr_pss(dn_sign)
    server_keystore["key-sign"] = key_pair_rsa_sign["key"]
    san = [f'URI.1 = {uuid.uuid4().urn}']
    server_keystore["crt-sign"] = sign_csr(key_pair_rsa_sign["pub"], dn_sign, san)


def create_server_certs():
    """
    Creates server side certificates
    :return: Nothing
    """
    global server_key_files, server_keystore, config

    same_enc_sign_cert = config["config"]["same_enc_sign_cert"]
    if not Path(server_key_files["key"]).is_file() or not Path(server_key_files["crt"]).is_file():
        print("create new encryption cert\n")
        create_server_certs_enc()
        for f_item in ["key", "crt"]:
            with open(server_key_files[f_item], "w") as f:
                f.write(server_keystore[f_item])
            f.close()
    else:
        for f_item in ["key", "crt"]:
            with open(server_key_files[f_item], "r") as f:
                server_keystore[f_item] = f.read()
            f.close()

    server_keystore["key-sign"] = server_keystore["key"]
    server_keystore["crt-sign"] = server_keystore["crt"]

    if not Path(server_key_files["key-sign"]).is_file() or not Path(server_key_files["crt-sign"]).is_file():
        print("create new signing cert\n")
        if not same_enc_sign_cert:
            create_server_certs_sign()
        for f_item in ["key-sign", "crt-sign"]:
            with open(server_key_files[f_item], "w") as f:
                f.write(server_keystore[f_item])
            f.close()
    else:
        for f_item in ["key-sign", "crt-sign"]:
            with open(server_key_files[f_item], "r") as f:
                server_keystore[f_item] = f.read()
            f.close()


def decrypt_str(message):
    """
    Decrypts a CMS message
    :param message: CMS enveloped message
    :return: Decrypted text
    """
    filename = f'/tmp/{get_temp_filename()}'
    filename_encrypted = f'{filename}.pem'
    filename_plain = f'{filename}.plain'
    pem_file = open(filename_encrypted, 'w')
    pem_file.write(message)
    pem_file.close()
    cmd = [
        "openssl",
        "cms",
        "-decrypt",
        "-inform", "PEM",
        "-in", filename_encrypted,
        "-inkey", server_key_files["key"],
        "-recip", server_key_files["crt"],
        "-out", filename_plain
    ]
    res_text = ""
    try:
        exec_cmd(cmd)
        with open(filename_plain, "r") as plain:
            res_text = plain.read()
        plain.close()
        os.unlink(filename_plain)
    except (OSError, subprocess.CalledProcessError) as err:
        logging.error("decrypt_str failed: %s", err)
    finally:
        os.unlink(filename_encrypted)

    return res_text


def verify_str(message):
    """
    Cerifies a CMS signed message
    :param message: CMS signed message
    :return: Dictionary with content, certs used for signing and verification result
    """
    filename = f'/tmp/{get_temp_filename()}'
    filename_in = f'{filename}.pem'
    filename_plain = f'{filename}.plain'
    filename_certs = f'{filename}.crt'
    with open(filename_in, 'w') as in_file:
        in_file.write(message)
    in_file.close()

    cmd = [
        "openssl",
        "cms",
        "-verify",
        "-inform", "PEM",
        "-in", f'{filename_in}',
        "-inkey", server_key_files["key"],
        "-recip", server_key_files["crt"],
        "-CAfile", server_key_files["ca"],
        "-out", f'{filename_plain}',
        "-certsout", f'{filename_certs}'
    ]
    try:
        res = exec_cmd(cmd)
        with open(filename_plain, "r") as f_plain_text:
            plain_text = f_plain_text.read()
        f_plain_text.close()
        with open(filename_certs, "r") as f_certs:
            certs = f_certs.read()
        f_certs.close()
        return {"content": plain_text,
                "certs": certs,
                "result": res.stderr.decode("utf8").find("Verification successful") != -1}
    except OSError as err:
        logging.error("verify_str failed: %s", err)
    finally:
        unlink_filenames = [filename_in, filename_plain, filename_certs]
        for unlink_filename in unlink_filenames:
            os.unlink(unlink_filename)


def encrypt_str(cert, message):
    """
    Encrypts message
    :param cert: Certificate for encryption
    :param message: Plain text message
    :return: CMS enveloped encrypted message
    """
    filename = f'/tmp/{get_temp_filename()}'
    filename_plain = f'{filename}.plain'
    filename_cert = f'{filename}.crt'
    filename_enc = f'{filename}.pem'
    with open(filename_plain, 'w') as f_plain:
        f_plain.write(message)
    f_plain.close()
    with open(filename_cert, 'w') as f_cert:
        f_cert.write(cert)
    f_cert.close()

    cmd = [
        "openssl",
        "cms",
        "-encrypt",
        "-outform", "PEM",
        "-in", f'{filename_plain}',
        "-recip", filename_cert,
        "-keyopt", "rsa_padding_mode:oaep",
        "-aes-256-cbc",
        "-out", f'{filename_enc}'
    ]
    res = exec_cmd(cmd)
    logging.info(res)
    with open(filename_enc, "r") as f_enc:
        encrypted = f_enc.read()

    unlink_files = [filename_plain, filename_cert, filename_enc]
    for unlink_file in unlink_files:
        os.unlink(unlink_file)

    return encrypted


def sign_str(message, pss=False):
    """
    Signs message
    :param message: Plain text message to be signed
    :param pss: Set to True if PSS padding mode should be used
    :return: CMS enveloped signed message
    """
    filename = f'/tmp/{get_temp_filename()}'
    filename_in = f'{filename}.plain'
    filename_signed = f'{filename}.pem'
    with open(filename_in, 'w') as in_file:
        in_file.write(message)
    in_file.close()

    if pss:
        cmd = [
            "openssl",
            "cms",
            "-sign",
            "-nodetach",
            "-outform", "PEM",
            "-in", f'{filename_in}',
            "-inkey", server_key_files["key-sign"],
            "-signer", server_key_files["crt-sign"],
            "-keyopt", "rsa_padding_mode:pss",
            "-keyopt", "rsa_pss_saltlen:20",
            "-keyopt", "rsa_mgf1_md:sha1",
            "-CAfile", server_key_files["ca"],
            "-out", f'{filename_signed}'
        ]
    else:
        cmd = [
            "openssl",
            "cms",
            "-sign",
            "-nodetach",
            "-outform", "PEM",
            "-in", f'{filename_in}',
            "-inkey", server_key_files["key-sign"],
            "-signer", server_key_files["crt-sign"],
            "-CAfile", server_key_files["ca"],
            "-out", f'{filename_signed}'
        ]
    res = exec_cmd(cmd)
    logging.info(res)

    with open(filename_signed, "r") as f_cms:
        cms = f_cms.read()
    f_cms.close()

    unlink_files = [filename_in, filename_signed]
    for unlink_file in unlink_files:
        os.unlink(unlink_file)

    return cms


def load_config():
    """
    Loads configuration file config.json
    Used by get_config()
    :return: Nothing
    """
    global config

    with open("config.json") as f:
        json_config = f.read()
    f.close()
    config = json.loads(json_config)


def get_config():
    """
    Loads configuration and adds keystore
    :return: Configuration as JSON
    """
    global config, server_keystore

    load_config()
    config["config"]["remotekeystore"]["ca"] = server_keystore["ca"]
    config["config"]["remotekeystore"]["server"] = server_keystore["crt"]
    return json.dumps(config)


def get_cert_data(pem):
    """
    Reads some data from certificate:
      * Subject
      * Subject Alternative Names
    :param pem: Certificate in PEM format
    :return: Dictionary with subject (dn) and san
    """
    cert_data = {}
    pem_filename = f'/tmp/{get_temp_filename()}.pem'
    with open(pem_filename, "w") as f:
        f.write(pem)
    f.close()
    cmd = [
        "openssl",
        "x509",
        "-noout",
        "-text",
        "-in", pem_filename
    ]
    try:
        res = exec_cmd(cmd)
    except subprocess.CalledProcessError as err:
        logging.error(err.stderr.decode("utf8"))
        return cert_data

    regex = re.compile("^\\s*X509v3 Subject Alternative Name:.*\\s*URI:urn:uuid:(\\S+)$", re.MULTILINE)
    regex_out = regex.search(res.stdout.decode("utf8"))
    if regex_out is not None:
        cert_data["san"] = regex_out.group(1)
    else:
        logging.error("UUID: No match")

    regex = re.compile("^\\s*Subject:\\s*(.+)$", re.MULTILINE)
    regex_out = regex.search(res.stdout.decode("utf8"))
    if regex_out is not None:
        cert_data["dn"] = regex_out.group(1)
    else:
        logging.error("Subject: No match")

    os.remove(pem_filename)

    return cert_data


def renew(cms):
    """
    Renews a certificate. Client has to send a CMS encrypted and signed message with CSR.
    If signature is authentic CSR will be signed. Certificate attributes are taken from
    signature certificate.
    :param cms: CMS encrypted and signed message
    :return: Result as JSON
    """
    response = {"success": False}
    try:
        decrypted_data = decrypt_str(cms)
        signed_data = verify_str(decrypted_data)            # validate signed message
        user_cert = signed_data["certs"]                    # get user certificate from signed message
        csr = signed_data["content"]\
            .replace("\\n", "\n")\
            .replace("\"", "")                              # should contain new CSR
        if bool(signed_data["result"]):                     # IMPORTANT: Reject if not verified
            logging.info("user_cert: %s\n", user_cert)
            logging.info("csr: %s\n", csr)
            cert_data = get_cert_data(user_cert)            # Use data from validated cert, not from csr
            logging.info("cert_data: %s\n", cert_data)
            uuid_urn = f'URI.1 = {uuid.UUID(cert_data["san"]).urn}'
            dn = convert_dn(cert_data["dn"])
            crt = sign_csr(csr, dn, uuid_urn)
            response["success"] = True
            response["crt"] = crt
            signed_response = sign_str(json.dumps(response))
            enc_response = encrypt_str(user_cert, signed_response)
            return json.dumps(enc_response)
        else:
            logging.error("Validation of signature failed")
    except (OSError, JSONDecodeError) as err:
        logging.error("Invalid Access renew", err)

    return json.dumps({"err": "Invalid request"})


def login(cms):
    """
    Authenticates a user. For demo purposes every password is accepted.
    If authentication is successful, enclosed CSR will be signed.
    :param cms: CMS encrypted message with credentials and PKCS#10 CSR
    :return: In case of success an signed certificate, in case of failure an error message
    """
    decrypted_data_json = decrypt_str(cms)
    decrypted_data = json.loads(decrypted_data_json)
    read_data = "{login: false}"
    if decrypted_data["csr"] is not None \
            and decrypted_data["username"] is not None \
            and decrypted_data["password"] is not None:
        username = decrypted_data["username"]
        password = decrypted_data["password"]
        uuid_urn = f'URI.1 = {uuid.uuid4().urn}'
        csr = str(decrypted_data["csr"]).replace('\r\n', "\n")
        logging.info("decryptedText:\nUsername: %s\nPassword: %s",
                     username,
                     password
                     )
        crt = sign_csr(csr, f'/CN={username}', [uuid_urn])
        read_data = json.dumps({
            "login": "true",
            "crt": crt
        })

        return read_data
    else:
        logging.info("bad login data")
    return read_data


def generate_payload(req):
    """
    Creates a demo payload. This is a demo for an arbitrary business logic.
    :param req: JSON request e.g. "I want something from you"
    :return: Response in JSON format
    """
    logging.info(f'Do something with {req}')
    return json.dumps({
        "msg1": "Hello world 1!",
        "msg2": "Hello world 2!"
    })


def do_message(cms):
    """
    The workhorse: Every message must pass this function and will be authenticated.
    Typical use case is
        * Client creates JSON request, encrypt and sign it and sends it to this function
        * This function validates request and forwards in case of success plain text to business logic
    :param cms: CMS signed and encrypted message with payload
    :return: CMS signed and encrypted message with response
    """
    try:
        # decrypt and verify received message
        decrypted_data = decrypt_str(cms)                  # decrypt incoming message
        signed_data = verify_str(decrypted_data)           # validate signed message
        user_cert = signed_data["certs"]                   # get user certificate from signed message
        logging.info(f'signed message: {signed_data}')     # display encrypted message received from client

        # send a signed and encrypted message
        content = json.loads(signed_data["content"])
        if re.search("^Mocha:.*", content):
            resp_signed = sign_str(content)
        else:
            resp_signed = sign_str(                            # sign plain text with servers private key
                generate_payload(json.dumps({"req1": "My request 1", "req2": "My request 2"}))
            )
        resp = encrypt_str(user_cert, resp_signed)         # encrypt message with clients certificate
    except OSError as err:
        logging.error("Invalid Access do_message", err)
        resp = "Invalid Access"
    return json.dumps(resp)


class S(BaseHTTPRequestHandler):
    """
    A small demo web server which provides all functions needed by client
    """
    def _set_response(self):
        plaintext_files = ["message.json", "renew.json"]
        filename = str(self.path)[1:]
        if filename is None or filename == "":
            filename = "genkey.html"
        try:
            self.send_response(200)
            if filename in plaintext_files:
                content_type = "text/plain"
            else:
                kind = filetype.guess(filename)
                content_type = 'application/octetstream'
                if kind is None:
                    if filename.endswith("html"):
                        content_type = 'text/html'
                    elif filename.endswith("js"):
                        content_type = 'text/javascript'
                    elif filename.endswith("css"):
                        content_type = 'text/css'
                    elif filename.endswith("json"):
                        content_type = 'application/json'
                else:
                    content_type = kind.mime

            self.send_header('Content-type', content_type)
            self.send_header('Access-Control-Allow-Origin', 'null')  # DO NOT USE IN PRODUCTION
            self.send_header('Access-Control-Allow-Headers', 'Content-type')
            self.end_headers()
        except OSError as err:
            self.send_response(404)
            logging.error(err)

    def do_OPTIONS(self):
        logging.info("OPTIONS request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))

        filename = str(self.path)[1:]
        if filename is None or filename == "":
            filename = "genkey.html"
        try:
            with open(filename, "rb") as f:
                read_data = f.read()
            f.close()
            self._set_response()
            response = BytesIO()
            response.write(read_data)
            self.wfile.write(response.getvalue())
        except OSError as err:
            logging.error(f'File not found: {filename} {err}')
            self._set_response()
            response = BytesIO()
            response.write(bytes(f'File not found: {filename}', "utf8"))
            self.wfile.write(response.getvalue())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
        post_data = self.rfile.read(content_length)  # <--- Gets the data itself
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                     str(self.path), str(self.headers), post_data.decode('utf-8'))

        filename = str(self.path)[1:]
        logging.info("filename: %s", filename)

        if filename == "config.json":
            read_data = get_config()
        elif filename == "login.json":
            logging.info("login called")
            read_data = login(post_data.decode('utf-8'))
        elif filename == "message.json":
            logging.info("message called")
            read_data = do_message(post_data.decode('utf-8'))
        elif filename == "renew.json":
            logging.info("renew called")
            read_data = renew(post_data.decode('utf-8'))
        else:
            read_data = json.dumps({"error": "Invalid Request"})

        self._set_response()
        response = BytesIO()
        response.write(bytes(read_data, "utf8"))
        self.wfile.write(response.getvalue())


def run(server_class=HTTPServer, handler_class=S, port=8000):
    logging.basicConfig(level=logging.INFO)
    server_address = ('127.0.0.1', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    from sys import argv

    if Path(pid_file).is_file():
        print("Already running, please stop other process first")
        sys.exit(1)

    signal.signal(signal.SIGTERM, sigterm_handler)
    pidfile()
    load_config()
    init_pki()
    create_server_certs()
    get_config()

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()

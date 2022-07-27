from asn1crypto import cms,x509,pem
import sys
import os

p7bfile: str = sys.argv[1]

if (not os.path.isfile(p7bfile)):
    exit("File does not exist")
else:
    with open(p7bfile, 'rb') as p7f:
        p7b = cms.ContentInfo.load(p7f.read())

        for fpkicert in p7b['content']['certificates']:
            try:
                cert = x509.Certificate.load(fpkicert.dump())
            except Exception as e:
                print("Error loading certificate from p7b: ", e)
                continue
    
        cert_subj_rdn_type = list(cert.subject.native.keys())[-1]

        cert_subj_rdn_value = cert.subject.native[cert_subj_rdn_type]

        if (isinstance(cert_subj_rdn_value, list)):
            cert_subj_rdn_value = cert_subj_rdn_value[-1]

        cert_issuer_rdn_type = list(cert.issuer.native.keys())[-1]

        cert_issuer_rdn_value = cert.issuer.native[cert_issuer_rdn_type]

        if(isinstance(cert_issuer_rdn_value, list)):
            cert_issuer_rdn_value = cert_issuer_rdn_value[-1]

        filename = f"exports/{cert_subj_rdn_value}--to--{cert_issuer_rdn_value}--{cert.serial_number}.cer"

        print("Writing ", filename)
        try:
            with open(filename, 'wb') as certfile:
                pem_bytes = pem.armor('CERTIFICATE', cert.dump())
                certfile.write(pem_bytes)
        except Exception as e:
            print("Unable to open file ", filename, ": ", e)

        print("Number of certs: ", len(p7b['content']['certificates']))
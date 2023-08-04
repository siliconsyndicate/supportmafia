stage_cert:
	cd cert; ./stage-gen.sh; cd ..

prod_cert:
	cd cert; ./prod-gen.sh; cd ..

CA:
	cd cert; ./generate-ca.sh; cd ..

CSR:
	cd cert; ./generate-csr.sh; cd ..

SIGN:
	cd cert; ./ca-sign-certificate.sh; cd ..

.PHONY: stage_cert prod_cert CA CSR SIGN

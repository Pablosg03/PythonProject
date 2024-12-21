import rsa

public_key, private_key = rsa.newkeys(512)

with open("public_key.pem","wb") as pub_file:
    pub_file.write(public_key.save_pkcs1())

with open("private_key.pem","wb") as priv_file:
    priv_file.write(private_key.save_pkcs1())
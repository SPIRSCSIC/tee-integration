from flask import Flask, request
from werkzeug.serving import WSGIRequestHandler
import ssl
import hashlib

app = Flask(__name__)

# https://www.ajg.id.au/2018/01/01/mutual-tls-with-python-flask-and-werkzeug/
class PeerCertWSGIRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        environ['SSL_CLIENT_CERT'] = self.connection.getpeercert()
        return environ


@app.route("/")
def anonymization_schemes():
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    if client_cert is not None:
        print(hashlib.sha256(client_cert.encode()).hexdigest())
    return {"hello": "world"}



if __name__ == "__main__":
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    context.load_verify_locations(cafile='ca/ca.crt')
    app.run(ssl_context=context)

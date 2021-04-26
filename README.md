# OpenVPN API

An API that allows management of OpenVPN clients via a RESTful interface.  **Currently unstable and work in progress**.

## Building

    make build

## Usage

The command has a bunch of sane defaults, the only command line arguments most would want to
specifically set is the working directory, and the domain name of the server.

Running the command for the first time will setup a few things for you:

* server certificate
* server config
* keys
* client database

Specifying the working directory will cause everything to be dumped there:

    ovpn-api -w /etc/openvpn/server -d vpn.example.com

After running this you could expect the following files to be present in there:

* vpn.example.com.conf
* crl.pem
* clients.db

It will also create the client config directory in there so any clients created will have the
IP address assigned per file.

* ccd/bob@example.com

## REST Endpoints

### GET /clients

Lists all clients on the OpenVPN server.

### GET /client_ips

Lists all the client IP addresses assigned by the OpenVPN server.

### GET /client/:cn

Show the details for a specific client.

### GET /client/:cn/config

Dump the config for a specific client as plain text.

### POST /client/:cn

Create a new client.  This will assign an IP address to the client and return the config that
includes the client certificiate and private key.

### DELETE /client/:cn

Deletes a client and revokes the certificate.  This also regenerates the CRL file on disk.

### GET /crl

Dump the CRL as plain text.

### PUT /crl

Regenerate the CRL file on disk.

# TODO

- [ ] initialize the client database
- [ ] allow specifying passwords for the client keys
- [ ] allow specifying the public IP address of the server
- [ ] load server template from working directory
- [ ] allow regeneration of server config
- [ ] load client template from working directory
# HLF Easy

HLF Easy is a tool to simplify the process of setting up Hyperledger Fabric nodes. It is designed to be used in baremetal environment.

![Easy HLF.png](./docs/images/Easy%20HLF.png)

# Tutorial

### Pre requisites
- HLF Peer binaries
- HLF Orderer binaries



### Install fabric binaries

```bash
curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh && chmod +x install-fabric.sh
./install-fabric.sh 2.5.5
```

### Compile the code
```bash
go build -o hlf-easy ./main.go && sudo mv hlf-easy /usr/local/bin/hlf-easy   
```

### Follow the HLF meetup 2024

Complete the meetup 2024 to get a running network with 2 peer organizations and 1 orderer organization.

Repository: https://github.com/kfsoftware/meetup-k8s-hlf-2024

Youtube: https://www.youtube.com/watch?v=8qPXaRzrFiQ

### Init the certificate authority

After initializing the certificate authority, you can inspect the certificate authority to get the certificates.

All the certificates will be saved in $HOME/hlf-easy with a custom structure.

```bash

hlf-easy ca init --hosts=192.168.1.36 --hosts localhost --hosts 127.0.0.1 --hosts ca.localho.st --name=ca-1

hlf-easy ca inspect --name=ca-1 > localorg1-ca.yaml

```

### Initializing the peer certificates

Once we have the certificates generated we need to initialize the peer certificates.

First, we need to find our external IP address, this is the IP address that the network nodes will use to connect to the peer.

You can use `ifconfig` or `ip a` to find the IP address of the interface that is connected to the network.
```bash
export EXTERNAL_HOST=192.168.1.36 
```

And then, we can initialize the peer certificates.
```bash
hlf-easy peer init --hosts=${EXTERNAL_HOST} --hosts localhost --hosts 127.0.0.1 --hosts peer01.localho.st --ca-name=ca-1 --id=peer1 --local=true

hlf-easy peer init --hosts=${EXTERNAL_HOST} --hosts localhost --hosts 127.0.0.1 --hosts peer02.localho.st --ca-name=ca-1 --id=peer2 --local=true
```

### Starting the peers

```bash

hlf-easy peer start --id=peer1 --msp-id=LocalOrg1 --external-endpoint="${EXTERNAL_HOST}:7051" \
  --listen-address="0.0.0.0:7051" \
  --chaincode-address="0.0.0.0:7052" \
  --events-address="0.0.0.0:7053" \
  --operations-listen-address="0.0.0.0:7054" \
  --mgmt-address="0.0.0.0:7055"


hlf-easy peer start --id=peer2 --msp-id=LocalOrg1 --external-endpoint="${EXTERNAL_HOST}:7061" \
  --listen-address="0.0.0.0:7061" \
  --chaincode-address="0.0.0.0:7062" \
  --events-address="0.0.0.0:7063" \
  --operations-listen-address="0.0.0.0:7064" \
  --mgmt-address="0.0.0.0:7065"
```
### Enroll the admin and client

After the peer is started, we can enroll the admin and client using our local ca
```bash

hlf-easy ca enroll --name=ca-1 --local=true --type=admin --common-name=admin > peer-admin.yaml

hlf-easy ca enroll --name=ca-1 --local=true --type=client --common-name=client > peer-client.yaml
```

### Joining a network

Once the peer is started and the admin is enrolled, we can join the peer to a network, for this, we need to have a running network, the variables to get the orderer certificate and the URLs are based on the 2024 HLF workshop mentioned above. 

```bash

kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" > orderer0-tls.pem

hlf-easy peer join --id=peer1 --channel=demo2 --identity=peer-admin.yaml --orderer-url=grpcs://orderer0-ord.localho.st:443 --orderer-tls-cert=orderer0-tls.pem

hlf-easy peer join --id=peer2 --channel=demo2 --identity=peer-admin.yaml --orderer-url=grpcs://orderer0-ord.localho.st:443 --orderer-tls-cert=orderer0-tls.pem
```
### Setting the anchor peers
```bash
hlf-easy peer anchorpeers set --id=peer1 --channel=demo2 --identity=peer-admin.yaml \
  --orderer-url=grpcs://orderer0-ord.localho.st:443 --orderer-tls-cert=orderer0-tls.pem \
  --anchor-peers="${EXTERNAL_HOST}:7051" --anchor-peers="${EXTERNAL_HOST}:7061"



```

## Roadmap

- [ ] Enroll using Fabric CA instead of local CA
- [ ] Docs for setting up and joining orderers
- [ ] Admin UI for Peer
  - [ ] Add detail of the peer + process stats (CPU, memory, requests)
  - [ ] Add logs
  - [ ] Add chaincode support
  - [ ] Add operations: restart, stop, start, upgrade, certificate renewal
# go-secp256k1-zkp

This repo aims to provide the CGO bindings for the modules listed below of the native [secp256k1-zkp C library](https://github.com/ElementsProject/secp256k1-zkp) (Elements version):

## 🛣 Roadmap

- [x] `secp256k1`
- [x] `secp256k1_ecdh`
- [x] `secp256k1_generator`
- [x] `secp256k1_rangeproof`
- [x] `secp256k1_surjectionproof`

## Install

```sh
$ go get -u github.com/vulpemventures/go-secp256k1-zkp
```

## 🖥 Development

- Clone the repository:

```sh
$ git clone git@github.com:vulpemventures/go-secp256k1-zkp.git
```

- Enter into the project folder and install depenedencies (optional if using _go mod_):

```sh
$ cd go-secp256k1-zkp
$ go get -t -v ./...
```

- Checkout [Elements/secp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp) submodule:

```sh
$ git submodule update --init
```

- Run tests:

```sh
$ go test ./... -v -race -count=1
```

## License [MIT](LICENSE)

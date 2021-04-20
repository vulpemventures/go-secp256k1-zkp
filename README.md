# go-secp256k1-zkp

This repo aims to provide the CGO bindings for the modules listed below of the native [secp256k1-zkp C library](https://github.com/ElementsProject/secp256k1-zkp) (Elements version):<br>
This project gets inspiration from [olegabu/secp256k1-zkp](https://github.com/olegabu/go-secp256k1-zkp) but uses the native lib ElementsProject/secp256k1-zkp instead of [mimblewimble/secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp)

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

- Run tests:

```sh
$ go test ./... -v -race -count=1
```

## License [MIT](LICENSE)

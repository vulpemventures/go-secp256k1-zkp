package secp256k1_test

import (
	"encoding/hex"
	"reflect"
	"testing"
	"vulpemventures/go-secp256k1-zkp"
)

func TestEcdh(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	type args struct {
		ctx     *secp256k1.Context
		pubKey  string
		privKey string
	}
	tests := []struct {
		name          string
		args          args
		want          int
		wantSecretKey string
		wantErr       bool
	}{
		{
			name: "1",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "d90314455f64c385db12f629c2adbecc576baebdfe70905a412747a689872760",
			},
			want:          1,
			wantSecretKey: "f66a0881818550bcd6ad23fb80f58d01b57b1b4f2aafec5e4d3ab53a5fa5c6c6",
			wantErr:       false,
		},
		{
			name: "2",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "9bf85f75c45152cf42ade21db0e1621b01d5ac5ae8f97467e8b3197b9c55ac10",
			},
			want:          1,
			wantSecretKey: "f7e34787897e317b304a4c5b639fb32711a76e10e8a94ca0086768be24a0c800",
			wantErr:       false,
		},
		{
			name: "3",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "e4392d6ac2abd286eca682a726230af4906ae3211d00f602a674d9162d3247e8",
			},
			want:          1,
			wantSecretKey: "4fe7858b8886c5aa7a6152329fdf18ab46ff2fdd71f030697e53572aa287f5d1",
			wantErr:       false,
		},
		{
			name: "4",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "32ba8137ca4f3fd1ae3b8180bf3f53e2f0b4c7a3c39236fb1152600c0f9950f5",
			},
			want:          1,
			wantSecretKey: "95fe82db4ea63bc3145c41fa17243c804090452473d443e77ec81a3a2d894a35",
			wantErr:       false,
		},
		{
			name: "5",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "4e3da01ed8a8c5f29539eaf435fb9ff959fea677589df81867ad949b95a00227",
			},
			want:          1,
			wantSecretKey: "947096ab953d2c0123c113c4fad0494eba60b8f9be5a2a9dfc414bbb3a3d5c14",
			wantErr:       false,
		},
		{
			name: "6",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "b295892920f72b4d5546eeb6e0868adc719c71a27571ccfd15179571566b5b7e",
			},
			want:          1,
			wantSecretKey: "b783846294b86fe637af3a885862914530d3c07e66fdfaf8093ad34ab2de1fed",
			wantErr:       false,
		},
		{
			name: "7",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "469ff0439a67397e305a22b30b68cea2f8c38562a19103b973dd7589b8d8693c",
			},
			want:          1,
			wantSecretKey: "469c6d7382a5a22be7e42d4d77b7e9c7832dacd2278481d2b9116b3d272a6dbf",
			wantErr:       false,
		},
		{
			name: "8",
			args: args{
				ctx:     ctx,
				pubKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				privKey: "ae674cb62376a9b1bfc437484d8d5c401ccf61e9d62af08c041eab8c6b75b355",
			},
			want:          1,
			wantSecretKey: "4964afacdf21ee9fa801e7a854ad121cdd8d385f0ed4e5bef665c2eb05e9800d",
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alicePrivateKeyBytes, err := hex.DecodeString(tt.args.privKey)
			if err != nil {
				t.Error(err)
			}

			bobPubKeyBytes, err := hex.DecodeString(tt.args.pubKey)
			if err != nil {
				t.Error(err)
			}

			_, bobPubKey, err := secp256k1.EcPubkeyParse(ctx, bobPubKeyBytes)
			if err != nil {
				t.Error(err)
			}
			got, secKey, err := secp256k1.Ecdh(tt.args.ctx, bobPubKey, alicePrivateKeyBytes)
			secretKey := hex.EncodeToString(secKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Ecdh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Ecdh() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(secretKey, tt.wantSecretKey) {
				t.Errorf("Ecdh() got1 = %v, want %v", secretKey, tt.wantSecretKey)
			}
		})
	}
}

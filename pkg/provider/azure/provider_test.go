// Package aws contains the provider implementation for AWS.
package azure

import (
	"context"
	"fmt"
	"testing"

	"github.com/quortex/kubestatic/pkg/provider"
)

func TestCreateAddress(t *testing.T) {
	pvd, err := NewProvider()
	if err != nil {
		t.Error(err)
	}

	addr, err := pvd.CreateAddress(context.Background())
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("address is %v", addr)
}

func TestDeleteAddress(t *testing.T) {
	pvd, err := NewProvider()

	if err != nil {
		t.Error(err)
	}

	err = pvd.DeleteAddress(context.Background(), "kubestatic-PaT8ODA4jIs")

	if err != nil {
		t.Error(err)
	}
	fmt.Println("Deleted success")
}

func TestGetAddress(t *testing.T) {
	pvd, err := NewProvider()

	if err != nil {
		t.Error(err)
	}

	addr, err := pvd.GetAddress(context.Background(), "800b4519-89d5-4861-be19-c0346657b845")

	if err != nil {
		t.Error(err)
	}

	fmt.Printf("address is %v", addr)
}

func TestAssociateAddress(t *testing.T) {
	pvd, err := NewProvider()

	if err != nil {
		t.Error(err)
	}

	var asso provider.AssociateAddressRequest
	asso.AddressID = "kubestatic-uJvhfhjpRG"
	asso.NetworkInterfaceID = "aks-workflow-66522159-vmss"

	err = pvd.AssociateAddress(context.Background(), asso)

	if err != nil {
		t.Error(err)
	}
	fmt.Println("success")
}

//func Test_azureProvider_GetInstance(t *testing.T) {
//	type fields struct {
//		ipClient  *network.PublicIPAddressesClient
//		nsgClient *network.SecurityGroupsClient
//	}
//	type args struct {
//		ctx        context.Context
//		instanceID string
//	}
//	tests := []struct {
//		name    string
//		fields  fields
//		args    args
//		want    *provider.Instance
//		wantErr bool
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			p := &azureProvider{
//				ipClient:  tt.fields.ipClient,
//				nsgClient: tt.fields.nsgClient,
//			}
//			got, err := p.GetInstance(tt.args.ctx, tt.args.instanceID)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("azureProvider.GetInstance() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("azureProvider.GetInstance() = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}

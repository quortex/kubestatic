package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	gomock "go.uber.org/mock/gomock"
	kmetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/internal/provider"
	"github.com/quortex/kubestatic/internal/provider/aws/mocks"
)

var _ = Describe("AWSProvider", func() {
	var (
		mockCtrl      *gomock.Controller
		mockec2Client *mocks.Mockec2Client
		p             provider.Provider
		clusterID     string
		filters       []types.Filter
		tags          []types.Tag
	)

	ctx := context.Background()
	log := logf.Log.WithName("aws-provider-test")
	clusterID = "cluster-id"
	vpcID := "vpc-id"

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockec2Client = mocks.NewMockec2Client(mockCtrl)

		// Inject the mock EC2 into the provider
		p = newProviderWithClient(mockec2Client, 5*time.Minute, 10*time.Minute, clusterID, vpcID)
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Context("ReconcileFirewallRulesDeletion", func() {
		var nodeName, testID, groupID, sgName, eniID, eni01ID string

		BeforeEach(func() {
			testID = rand.String(5)
			nodeName = "node-" + testID
			groupID = "sg-" + testID
			sgName = fmt.Sprintf("test-%s-sg", testID)
			eniID = "eni-" + testID
			eni01ID = "eni-1-" + testID
			filters = []types.Filter{
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyNodeName)),
					Values: []string{nodeName},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyClusterID)),
					Values: []string{clusterID},
				},
				{
					Name:   aws.String("vpc-id"),
					Values: []string{vpcID},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyManaged)),
					Values: []string{"true"},
				},
			}
		})

		It("should return an error when an AWS API call (DescribeSecurityGroups) fails", func() {
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{}, fmt.Errorf("describe security groups error")
				})

			err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName, "")
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to list security groups: describe security groups error",
			}))
		})

		It("should return nil when the security group is not found", func() {
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{},
					}, nil
				})
			err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName, "")
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return an error when an AWS API call (DescribeNetworkInterfaces) fails", func() {
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId:   aws.String(groupID),
								GroupName: aws.String(sgName),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
					Expect(input.Filters).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
						"Name":   PointTo(Equal("group-id")),
						"Values": ConsistOf(groupID),
					})))
					return &ec2.DescribeNetworkInterfacesOutput{
						NetworkInterfaces: []types.NetworkInterface{},
					}, fmt.Errorf("describe network interfaces error")
				})

			err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName, "")
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to list network interfaces: describe network interfaces error",
			}))
		})

		It("should return an error when an AWS API call (ModifyNetworkInterfaceAttribute) fails", func() {
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId:   aws.String(groupID),
								GroupName: aws.String(sgName),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
					Expect(input.Filters).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
						"Name":   PointTo(Equal("group-id")),
						"Values": ConsistOf(groupID),
					})))
					return &ec2.DescribeNetworkInterfacesOutput{
						NetworkInterfaces: []types.NetworkInterface{
							{
								NetworkInterfaceId: aws.String(eniID),
								Attachment: &types.NetworkInterfaceAttachment{
									AttachmentId: aws.String("eni-attach-" + testID),
									InstanceId:   aws.String("i-" + testID),
								},
								Groups: []types.GroupIdentifier{
									{
										GroupId:   aws.String(groupID),
										GroupName: aws.String(sgName),
									},
									{
										GroupId:   aws.String("sg-01"),
										GroupName: aws.String("sg-01"),
									},
									{
										GroupId:   aws.String("sg-02"),
										GroupName: aws.String("sg-02"),
									},
								},
							},
							{
								NetworkInterfaceId: aws.String(eni01ID),
								Attachment: &types.NetworkInterfaceAttachment{
									AttachmentId: aws.String("eni-attach-1" + testID),
									InstanceId:   aws.String("i-1-" + testID),
								},
								Groups: []types.GroupIdentifier{
									{
										GroupId:   aws.String(groupID),
										GroupName: aws.String(sgName),
									},
									{
										GroupId:   aws.String("sg-01"),
										GroupName: aws.String("sg-01"),
									},
									{
										GroupId:   aws.String("sg-02"),
										GroupName: aws.String("sg-02"),
									},
								},
							},
						},
					}, nil
				})

			mockec2Client.EXPECT().
				ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
					Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
					Expect(input.Groups).To(ConsistOf("sg-01", "sg-02"))
					return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
				})
			mockec2Client.EXPECT().
				ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
					Expect(input.NetworkInterfaceId).To(PointTo(Equal(eni01ID)))
					Expect(input.Groups).To(ConsistOf("sg-01", "sg-02"))
					return &ec2.ModifyNetworkInterfaceAttributeOutput{}, fmt.Errorf("modify network interface attribute error")
				})

			err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName, "")
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to modify network interface attribute: modify network interface attribute error",
			}))
		})

		It("should return an error when an AWS API call (DeleteSecurityGroup) fails", func() {
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId:   aws.String(groupID),
								GroupName: aws.String(sgName),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
					Expect(input.Filters).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
						"Name":   PointTo(Equal("group-id")),
						"Values": ConsistOf(groupID),
					})))
					return &ec2.DescribeNetworkInterfacesOutput{
						NetworkInterfaces: []types.NetworkInterface{
							{
								NetworkInterfaceId: aws.String(eniID),
								Attachment: &types.NetworkInterfaceAttachment{
									AttachmentId: aws.String("eni-attach-" + testID),
									InstanceId:   aws.String("i-" + testID),
								},
								Groups: []types.GroupIdentifier{
									{
										GroupId:   aws.String(groupID),
										GroupName: aws.String(sgName),
									},
									{
										GroupId:   aws.String("sg-01"),
										GroupName: aws.String("sg-01"),
									},
									{
										GroupId:   aws.String("sg-02"),
										GroupName: aws.String("sg-02"),
									},
								},
							},
							{
								NetworkInterfaceId: aws.String(eni01ID),
								Attachment: &types.NetworkInterfaceAttachment{
									AttachmentId: aws.String("eni-attach-1" + testID),
									InstanceId:   aws.String("i-1-" + testID),
								},
								Groups: []types.GroupIdentifier{
									{
										GroupId:   aws.String(groupID),
										GroupName: aws.String(sgName),
									},
									{
										GroupId:   aws.String("sg-01"),
										GroupName: aws.String("sg-01"),
									},
									{
										GroupId:   aws.String("sg-02"),
										GroupName: aws.String("sg-02"),
									},
								},
							},
						},
					}, nil
				})

			mockec2Client.EXPECT().
				ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
					Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
					Expect(input.Groups).To(ConsistOf("sg-01", "sg-02"))
					return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
				})
			mockec2Client.EXPECT().
				ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
					Expect(input.NetworkInterfaceId).To(PointTo(Equal(eni01ID)))
					Expect(input.Groups).To(ConsistOf("sg-01", "sg-02"))
					return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
				})
			mockec2Client.EXPECT().
				DeleteSecurityGroup(ctx, gomock.AssignableToTypeOf(&ec2.DeleteSecurityGroupInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DeleteSecurityGroupInput, _ ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
					Expect(input.GroupId).To(PointTo(Equal(groupID)))
					return &ec2.DeleteSecurityGroupOutput{}, fmt.Errorf("delete security group error")
				})

			err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName, "")
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to delete security group: delete security group error",
			}))
		})

		It("should return nil when no aws api call returns an error", func() {
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId:   aws.String(groupID),
								GroupName: aws.String(sgName),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
					Expect(input.Filters).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
						"Name":   PointTo(Equal("group-id")),
						"Values": ConsistOf(groupID),
					})))
					return &ec2.DescribeNetworkInterfacesOutput{
						NetworkInterfaces: []types.NetworkInterface{
							{
								NetworkInterfaceId: aws.String(eniID),
								Attachment: &types.NetworkInterfaceAttachment{
									AttachmentId: aws.String("eni-attach-" + testID),
									InstanceId:   aws.String("i-" + testID),
								},
								Groups: []types.GroupIdentifier{
									{
										GroupId:   aws.String(groupID),
										GroupName: aws.String(sgName),
									},
									{
										GroupId:   aws.String("sg-01"),
										GroupName: aws.String("sg-01"),
									},
									{
										GroupId:   aws.String("sg-02"),
										GroupName: aws.String("sg-02"),
									},
								},
							},
							{
								NetworkInterfaceId: aws.String(eni01ID),
								Attachment: &types.NetworkInterfaceAttachment{
									AttachmentId: aws.String("eni-attach-1" + testID),
									InstanceId:   aws.String("i-1-" + testID),
								},
								Groups: []types.GroupIdentifier{
									{
										GroupId:   aws.String(groupID),
										GroupName: aws.String(sgName),
									},
									{
										GroupId:   aws.String("sg-01"),
										GroupName: aws.String("sg-01"),
									},
									{
										GroupId:   aws.String("sg-02"),
										GroupName: aws.String("sg-02"),
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
					Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
					Expect(input.Groups).To(ConsistOf("sg-01", "sg-02"))
					return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
				})
			mockec2Client.EXPECT().
				ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
					Expect(input.NetworkInterfaceId).To(PointTo(Equal(eni01ID)))
					Expect(input.Groups).To(ConsistOf("sg-01", "sg-02"))
					return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
				})
			mockec2Client.EXPECT().
				DeleteSecurityGroup(ctx, gomock.AssignableToTypeOf(&ec2.DeleteSecurityGroupInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DeleteSecurityGroupInput, _ ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
					Expect(input.GroupId).To(PointTo(Equal(groupID)))
					return &ec2.DeleteSecurityGroupOutput{}, nil
				})

			err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName, "")
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("ReconcileExternalIPDeletion", func() {
		var (
			externalIP                          *v1alpha1.ExternalIP
			testID, associationID, allocationID string
		)

		BeforeEach(func() {
			testID = rand.String(5)
			associationID = "eipassoc-" + testID
			allocationID = "eipalloc-" + testID
			externalIP = &v1alpha1.ExternalIP{
				ObjectMeta: kmetav1.ObjectMeta{
					Name:      "external-ip-" + testID,
					Namespace: "default",
					Labels: map[string]string{
						"node-name": "node-" + testID,
					},
					Annotations: map[string]string{
						"kubestatic.io/managed": "true",
					},
					Finalizers: []string{
						"kubestatic.io/external-ip",
					},
				},
				Spec: v1alpha1.ExternalIPSpec{
					NodeName: "node-" + testID,
				},
			}
			filters = []types.Filter{
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyManaged)),
					Values: []string{"true"},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyClusterID)),
					Values: []string{clusterID},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyExternalIPName)),
					Values: []string{externalIP.Name},
				},
			}
		})

		It("should return an error when an AWS API call (DescribeAddresses) fails", func() {
			mockec2Client.EXPECT().
				DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeAddressesOutput{}, fmt.Errorf("describe addresses error")
				})

			err := p.ReconcileExternalIPDeletion(ctx, log, externalIP)
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to list addresses: describe addresses error",
			}))
		})

		It("should return nil when the address is not found", func() {
			mockec2Client.EXPECT().
				DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeAddressesOutput{
						Addresses: []types.Address{},
					}, nil
				})

			err := p.ReconcileExternalIPDeletion(ctx, log, externalIP)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return an error when an AWS API call (DisassociateAddress) fails", func() {
			mockec2Client.EXPECT().
				DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeAddressesOutput{
						Addresses: []types.Address{
							{
								AssociationId: aws.String(associationID),
								AllocationId:  aws.String(allocationID),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DisassociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.DisassociateAddressInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DisassociateAddressInput, _ ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
					Expect(input.AssociationId).To(PointTo(Equal(associationID)))
					return &ec2.DisassociateAddressOutput{}, fmt.Errorf("disassociate address error")
				})

			err := p.ReconcileExternalIPDeletion(ctx, log, externalIP)
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to disassociate address: disassociate address error",
			}))
		})

		It("should return an error when an AWS API call (ReleaseAddress) fails", func() {
			mockec2Client.EXPECT().
				DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeAddressesOutput{
						Addresses: []types.Address{
							{
								AssociationId: aws.String(associationID),
								AllocationId:  aws.String(allocationID),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DisassociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.DisassociateAddressInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DisassociateAddressInput, _ ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
					Expect(input.AssociationId).To(PointTo(Equal(associationID)))
					return &ec2.DisassociateAddressOutput{}, nil
				})
			mockec2Client.EXPECT().
				ReleaseAddress(ctx, gomock.AssignableToTypeOf(&ec2.ReleaseAddressInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ReleaseAddressInput, _ ...func(*ec2.Options)) (*ec2.ReleaseAddressOutput, error) {
					Expect(input.AllocationId).To(PointTo(Equal(allocationID)))
					return &ec2.ReleaseAddressOutput{}, fmt.Errorf("release address error")
				})

			err := p.ReconcileExternalIPDeletion(ctx, log, externalIP)
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to delete address: release address error",
			}))
		})

		It("should return nil when no aws api call returns an error", func() {
			mockec2Client.EXPECT().
				DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeAddressesOutput{
						Addresses: []types.Address{
							{
								AssociationId: aws.String(associationID),
								AllocationId:  aws.String(allocationID),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DisassociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.DisassociateAddressInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DisassociateAddressInput, _ ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
					Expect(input.AssociationId).To(PointTo(Equal(associationID)))
					return &ec2.DisassociateAddressOutput{}, nil
				})
			mockec2Client.EXPECT().
				ReleaseAddress(ctx, gomock.AssignableToTypeOf(&ec2.ReleaseAddressInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.ReleaseAddressInput, _ ...func(*ec2.Options)) (*ec2.ReleaseAddressOutput, error) {
					Expect(input.AllocationId).To(PointTo(Equal(allocationID)))
					return &ec2.ReleaseAddressOutput{}, nil
				})

			err := p.ReconcileExternalIPDeletion(ctx, log, externalIP)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("ReconcileExternalIP", func() {
		var (
			externalIP                                                                *v1alpha1.ExternalIP
			testID, instanceID, allocationID, associationID, publicIP, eniID, eni01ID string
		)

		BeforeEach(func() {
			testID = rand.String(5)
			allocationID = "eipalloc-" + testID
			externalIP = &v1alpha1.ExternalIP{
				ObjectMeta: kmetav1.ObjectMeta{
					Name:      "external-ip-" + testID,
					Namespace: "default",
					Labels: map[string]string{
						"node-name": "node-" + testID,
					},
					Annotations: map[string]string{
						"kubestatic.io/managed": "true",
					},
					Finalizers: []string{
						"kubestatic.io/external-ip",
					},
				},
				Spec: v1alpha1.ExternalIPSpec{
					NodeName: "node-" + testID,
				},
			}
			filters = []types.Filter{
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyManaged)),
					Values: []string{"true"},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyClusterID)),
					Values: []string{clusterID},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyExternalIPName)),
					Values: []string{externalIP.Name},
				},
			}
			tags = []types.Tag{
				{
					Key:   aws.String(string(TagKeyManaged)),
					Value: aws.String("true"),
				},
				{
					Key:   aws.String(string(TagKeyClusterID)),
					Value: aws.String(clusterID),
				},
				{
					Key:   aws.String(string(TagKeyExternalIPName)),
					Value: aws.String(externalIP.Name),
				},
				{
					Key:   aws.String(string(TagKeyInstanceID)),
					Value: aws.String(instanceID),
				},
			}
		})

		When("the instance ID is empty", func() {
			BeforeEach(func() {
				instanceID = ""
			})

			It("should return a pending state and an error when an AWS API call (DescribeAddresses) fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{}, fmt.Errorf("describe addresses error")
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStatePending),
					"Conditions": HaveExactElements(matchCondition(
						kmetav1.Condition{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionUnknown,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to list addresses: describe addresses error",
				}))
			})

			It("should return a pending state, specify in the condition when the maximum address is reached and an error when an AWS API call (AllocateAddress) fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{}, nil
					})
				mockec2Client.EXPECT().
					AllocateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AllocateAddressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AllocateAddressInput, _ ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error) {
						Expect(input.Domain).To(Equal(types.DomainTypeVpc))
						Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
							"ResourceType": Equal(types.ResourceTypeElasticIp),
							"Tags":         ConsistOf(tags),
						})))
						return &ec2.AllocateAddressOutput{}, &smithy.GenericAPIError{
							Code:    "AddressLimitExceeded",
							Message: "Too many addresses allocated",
							Fault:   smithy.FaultClient,
						}
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStatePending),
					"Conditions": HaveExactElements(matchCondition(
						kmetav1.Condition{
							Type:    v1alpha1.ExternalIPConditionReasonIPCreated,
							Status:  kmetav1.ConditionFalse,
							Reason:  v1alpha1.ExternalIPConditionReasonProviderError,
							Message: "Could not create address: The maximum number of addresses has been reached",
						}, "LastTransitionTime", "ObservedGeneration")),
				}))

				Expect(err).To(MatchError(&provider.Error{
					Code: "AddressLimitExceeded",
					Msg:  "failed to create address: api error AddressLimitExceeded: Too many addresses allocated",
				}))
			})

			It("should return a pending state and an error when an AWS API call (AllocateAddress) fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{}, nil
					})
				mockec2Client.EXPECT().
					AllocateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AllocateAddressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AllocateAddressInput, _ ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error) {
						Expect(input.Domain).To(Equal(types.DomainTypeVpc))
						Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
							"ResourceType": Equal(types.ResourceTypeElasticIp),
							"Tags":         ConsistOf(tags),
						})))
						return &ec2.AllocateAddressOutput{}, fmt.Errorf("allocate address error")
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStatePending),
					"Conditions": HaveExactElements(matchCondition(
						kmetav1.Condition{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.ExternalIPConditionReasonProviderError,
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))

				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to create address: allocate address error",
				}))
			})

			It("should return a pending state and an error when an AWS API call (DescribeAddresses after address creation) fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{}, nil
					})
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							append(
								filters,
								types.Filter{
									Name:   aws.String("allocation-id"),
									Values: []string{allocationID},
								},
							),
						))
						return &ec2.DescribeAddressesOutput{}, fmt.Errorf("describe addresses error")
					})
				mockec2Client.EXPECT().
					AllocateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AllocateAddressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AllocateAddressInput, _ ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error) {
						Expect(input.Domain).To(Equal(types.DomainTypeVpc))
						Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
							"ResourceType": Equal(types.ResourceTypeElasticIp),
							"Tags":         ConsistOf(tags),
						})))
						return &ec2.AllocateAddressOutput{
							AllocationId: aws.String(allocationID),
						}, nil
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStatePending),
					"Conditions": HaveExactElements(matchCondition(kmetav1.Condition{
						Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
						Status: kmetav1.ConditionTrue,
						Reason: v1alpha1.ExternalIPConditionReasonProviderError,
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))

				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to list addresses: describe addresses error",
				}))
			})

			When("the address is not associated to any instance", func() {
				It("should return a reserved state and specify IPCreation and NetworkInterfaceAssociation condition", func() {
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeAddressesOutput{}, nil
						})
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								append(
									filters,
									types.Filter{
										Name:   aws.String("allocation-id"),
										Values: []string{allocationID},
									}),
							))
							return &ec2.DescribeAddressesOutput{
								Addresses: []types.Address{
									{
										AllocationId: aws.String(allocationID),
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						AllocateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AllocateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.AllocateAddressInput, _ ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error) {
							Expect(input.Domain).To(Equal(types.DomainTypeVpc))
							Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
								"ResourceType": Equal(types.ResourceTypeElasticIp),
								"Tags":         ConsistOf(tags),
							})))
							return &ec2.AllocateAddressOutput{
								AllocationId: aws.String(allocationID),
							}, nil
						})

					status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.ExternalIPStateReserved),
						"Conditions": ConsistOf(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
							},
							{
								Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionFalse,
								Reason: v1alpha1.ExternalIPConditionReasonProviderError,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).ToNot(HaveOccurred())
				})
			})

			When("the address is associated to an instance", func() {
				associationID = "eipassoc-" + testID

				It("should return a reserved state and specify IPCreation and NetworkInterfaceAssociation condition and an error when an AWS API call (DisassociateAddress) fails", func() {
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeAddressesOutput{}, nil
						})
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								append(
									filters,
									types.Filter{
										Name:   aws.String("allocation-id"),
										Values: []string{allocationID},
									},
								),
							))
							return &ec2.DescribeAddressesOutput{
								Addresses: []types.Address{
									{
										AllocationId:  aws.String(allocationID),
										AssociationId: aws.String(associationID),
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						AllocateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AllocateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.AllocateAddressInput, _ ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error) {
							Expect(input.Domain).To(Equal(types.DomainTypeVpc))
							Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
								"ResourceType": Equal(types.ResourceTypeElasticIp),
								"Tags":         ConsistOf(tags),
							})))
							return &ec2.AllocateAddressOutput{
								AllocationId: aws.String(allocationID),
							}, nil
						})
					mockec2Client.EXPECT().
						DisassociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.DisassociateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DisassociateAddressInput, _ ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
							Expect(input.AssociationId).To(PointTo(Equal(associationID)))
							return &ec2.DisassociateAddressOutput{}, fmt.Errorf("disassociate address error")
						})

					status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.ExternalIPStateReserved),
						"Conditions": ConsistOf(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
							},
							{
								Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionFalse,
								Reason: v1alpha1.ExternalIPConditionReasonProviderError,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to disassociate address: disassociate address error",
					}))
				})

				It("should return a reserved state and specify IPCreation and NetworkInterfaceAssociation condition", func() {
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeAddressesOutput{}, nil
						})
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								append(
									filters,
									types.Filter{
										Name:   aws.String("allocation-id"),
										Values: []string{allocationID},
									},
								),
							))
							return &ec2.DescribeAddressesOutput{
								Addresses: []types.Address{
									{
										AllocationId:  aws.String(allocationID),
										AssociationId: aws.String(associationID),
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						AllocateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AllocateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.AllocateAddressInput, _ ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error) {
							Expect(input.Domain).To(Equal(types.DomainTypeVpc))
							Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
								"ResourceType": Equal(types.ResourceTypeElasticIp),
								"Tags":         ConsistOf(tags),
							})))
							return &ec2.AllocateAddressOutput{
								AllocationId: aws.String(allocationID),
							}, nil
						})
					mockec2Client.EXPECT().
						DisassociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.DisassociateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DisassociateAddressInput, _ ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
							Expect(input.AssociationId).To(PointTo(Equal(associationID)))
							return &ec2.DisassociateAddressOutput{}, nil
						})

					status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State":      Equal(v1alpha1.ExternalIPStateReserved),
						"InstanceID": BeNil(),
						"Conditions": ConsistOf(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
							},
							{
								Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionFalse,
								Reason: v1alpha1.ExternalIPConditionReasonProviderError,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).ToNot(HaveOccurred())
				})
			})
		})

		When("the instance ID is not empty", func() {
			BeforeEach(func() {
				instanceID = "i-" + testID
			})

			It("should return a pending state and an error when an AWS API call (DescribeAddresses) fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{}, fmt.Errorf("describe addresses error")
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStatePending),
					"Conditions": HaveExactElements(matchCondition(
						kmetav1.Condition{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionUnknown,
							Reason: v1alpha1.ExternalIPConditionReasonProviderError,
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to list addresses: describe addresses error",
				}))
			})

			It("should return a reserved state and an error when an AWS API call (DescribeInstances) fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{
							Addresses: []types.Address{
								{
									AllocationId:  aws.String(allocationID),
									AssociationId: aws.String(associationID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{}, fmt.Errorf("describe instances error")
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStateReserved),
					"Conditions": HaveExactElements(matchCondition(
						kmetav1.Condition{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to get instance: describe instances error",
				}))
			})

			It("should return a reserved state and an error when no instance is found with API call (DescribeInstances)", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{
							Addresses: []types.Address{
								{
									AllocationId:  aws.String(allocationID),
									AssociationId: aws.String(associationID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{},
						}, nil
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStateReserved),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "NotFoundError",
					Msg:  fmt.Sprintf("failed to get instance: instance with instance-id %s not found", instanceID),
				}))
			})

			It("should return a reserved state and an error when the instance has no ENI with public IP", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{
							Addresses: []types.Address{
								{
									AllocationId:  aws.String(allocationID),
									AssociationId: aws.String(associationID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStateReserved),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
						},
						{
							Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionUnknown,
							Reason: v1alpha1.ExternalIPConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(ContainSubstring("no network interface with public IP found")))
			})

			It("should return a reserved state and an error when the instance has no ENI with public IP", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{
							Addresses: []types.Address{
								{
									AllocationId:  aws.String(allocationID),
									AssociationId: aws.String(associationID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStateReserved),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
						},
						{
							Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionUnknown,
							Reason: v1alpha1.ExternalIPConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(ContainSubstring("no network interface with public IP found")))
			})

			When("the address has a network interface associated", func() {
				publicIP = "ip-" + testID
				eniID = "eni-" + testID
				eni01ID = "eni-01-" + testID
				It("should return an associated state if it's associated with the current instance", func() {
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeAddressesOutput{
								Addresses: []types.Address{
									{
										AllocationId:       aws.String(allocationID),
										AssociationId:      aws.String(associationID),
										NetworkInterfaceId: aws.String(eniID),
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eniID),
													},
												},
											},
										},
									},
								},
							}, nil
						})

					status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.ExternalIPStateAssociated),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
							},
							{
								Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).ToNot(HaveOccurred())
				})

				It("should return a reserved state and an error if it's associated with a different instance and the AWS API call (DisassociateAddress) fails", func() {
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeAddressesOutput{
								Addresses: []types.Address{
									{
										AllocationId:       aws.String(allocationID),
										AssociationId:      aws.String(associationID),
										NetworkInterfaceId: aws.String(eniID),
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eni01ID),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DisassociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.DisassociateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DisassociateAddressInput, _ ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
							Expect(input.AssociationId).To(PointTo(Equal(associationID)))
							return &ec2.DisassociateAddressOutput{}, fmt.Errorf("disassociate address error")
						})

					status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.ExternalIPStateReserved),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
							},
							{
								Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionFalse,
								Reason: v1alpha1.ExternalIPConditionReasonProviderError,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to disassociate address: disassociate address error",
					}))
				})

				It("should return an associate state when no AWS API call fails", func() {
					mockec2Client.EXPECT().
						DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeAddressesOutput{
								Addresses: []types.Address{
									{
										AllocationId:       aws.String(allocationID),
										AssociationId:      aws.String(associationID),
										NetworkInterfaceId: aws.String(eniID),
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eni01ID),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DisassociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.DisassociateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DisassociateAddressInput, _ ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
							Expect(input.AssociationId).To(PointTo(Equal(associationID)))
							return &ec2.DisassociateAddressOutput{}, nil
						})
					mockec2Client.EXPECT().
						AssociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AssociateAddressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.AssociateAddressInput, _ ...func(*ec2.Options)) (*ec2.AssociateAddressOutput, error) {
							Expect(input.AllocationId).To(PointTo(Equal(allocationID)))
							Expect(input.NetworkInterfaceId).To(PointTo(Equal(eni01ID)))
							return &ec2.AssociateAddressOutput{}, nil
						})

					status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State":      Equal(v1alpha1.ExternalIPStateAssociated),
						"InstanceID": PointTo(Equal(instanceID)),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
							},
							{
								Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.ExternalIPConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).ToNot(HaveOccurred())
				})
			})

			It("should return a reserved state and an error when the AWS API call (AssociateAddress) fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{
							Addresses: []types.Address{
								{
									AllocationId:  aws.String(allocationID),
									AssociationId: aws.String(associationID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					AssociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AssociateAddressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AssociateAddressInput, _ ...func(*ec2.Options)) (*ec2.AssociateAddressOutput, error) {
						Expect(input.AllocationId).To(PointTo(Equal(allocationID)))
						Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
						return &ec2.AssociateAddressOutput{}, fmt.Errorf("associate address error")
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.ExternalIPStateReserved),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
						},
						{
							Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.ExternalIPConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to associate address: associate address error",
				}))
			})

			It("should return an associate state when no AWS API call fails", func() {
				mockec2Client.EXPECT().
					DescribeAddresses(ctx, gomock.AssignableToTypeOf(&ec2.DescribeAddressesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeAddressesOutput{
							Addresses: []types.Address{
								{
									AllocationId:  aws.String(allocationID),
									AssociationId: aws.String(associationID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					AssociateAddress(ctx, gomock.AssignableToTypeOf(&ec2.AssociateAddressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AssociateAddressInput, _ ...func(*ec2.Options)) (*ec2.AssociateAddressOutput, error) {
						Expect(input.AllocationId).To(PointTo(Equal(allocationID)))
						Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
						return &ec2.AssociateAddressOutput{}, nil
					})

				status, err := p.ReconcileExternalIP(ctx, log, instanceID, externalIP)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State":      Equal(v1alpha1.ExternalIPStateAssociated),
					"InstanceID": PointTo(Equal(instanceID)),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.ExternalIPConditionReasonIPCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.ExternalIPConditionReasonIPCreated,
						},
						{
							Type:   v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.ExternalIPConditionReasonNetworkInterfaceAssociated,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Context("ReconcileFirewallRule", func() {
		var (
			firewallRule, firewallRule01                                                                        *v1alpha1.FirewallRule
			firewallrules                                                                                       []v1alpha1.FirewallRule
			testID, instanceID, nodeName, securityGroupID, securityGroup01ID, publicIP, eniID, eni01ID, eni02ID string
		)

		BeforeEach(func() {
			testID = rand.String(5)
			publicIP = "ip-" + testID
			eniID = "eni-" + testID
			eni01ID = "eni-01-" + testID
			eni02ID = "eni-02-" + testID
			instanceID = "i-" + testID
			securityGroupID = "sg-" + testID
			securityGroup01ID = "sg-01-" + testID
			nodeName = "node-" + testID
			firewallRule = &v1alpha1.FirewallRule{
				ObjectMeta: kmetav1.ObjectMeta{
					Name:      "firewallrule-" + testID,
					Namespace: "default",
				},
				Spec: v1alpha1.FirewallRuleSpec{
					NodeName:              &nodeName,
					Description:           "QxO FirewallRule for Input: 45814-48569",
					Direction:             v1alpha1.DirectionIngress,
					DisableReconciliation: false,
					FromPort:              5969,
					IPRanges: []*v1alpha1.IPRange{
						{
							CIDR:        "0.0.0.0/0",
							Description: "",
						},
					},
					Protocol: "TCP",
					ToPort:   aws.Int64(5969),
				},
			}
			firewallRule01 = &v1alpha1.FirewallRule{
				ObjectMeta: kmetav1.ObjectMeta{
					Name:      "firewallrule-01-" + testID,
					Namespace: "default",
				},
				Spec: v1alpha1.FirewallRuleSpec{
					NodeName:              &nodeName,
					Description:           "QxO FirewallRule for Input: 45814-48569",
					Direction:             v1alpha1.DirectionIngress,
					DisableReconciliation: false,
					FromPort:              5970,
					IPRanges: []*v1alpha1.IPRange{
						{
							CIDR:        "0.0.0.0/0",
							Description: "",
						},
					},
					Protocol: "TCP",
					ToPort:   aws.Int64(5970),
				},
			}
			firewallrules = []v1alpha1.FirewallRule{*firewallRule, *firewallRule01}
			filters = []types.Filter{
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyNodeName)),
					Values: []string{nodeName},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyClusterID)),
					Values: []string{clusterID},
				},
				{
					Name:   aws.String("vpc-id"),
					Values: []string{vpcID},
				},
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyManaged)),
					Values: []string{"true"},
				},
			}
			tags = []types.Tag{
				{
					Key:   aws.String(string(TagKeyManaged)),
					Value: aws.String("true"),
				},
				{
					Key:   aws.String(string(TagKeyClusterID)),
					Value: aws.String(clusterID),
				},
				{
					Key:   aws.String(string(TagKeyNodeName)),
					Value: aws.String(nodeName),
				},
				{
					Key:   aws.String(string(TagKeyInstanceID)),
					Value: aws.String(instanceID),
				},
			}
		})

		It("should return a pending state and an error when an AWS API call (DescribeInstances) fails", func() {
			mockec2Client.EXPECT().
				DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					Expect(input.InstanceIds).To(ConsistOf(instanceID))
					return &ec2.DescribeInstancesOutput{}, fmt.Errorf("describe instance error")
				})

			status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
			Expect(status).To(MatchFields(IgnoreExtras, Fields{
				"State":      Equal(v1alpha1.FirewallRuleStatePending),
				"Conditions": BeNil(),
			}))
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to get instance: describe instance error",
			}))
		})

		It("should return a pending state and an error when the instance is not found", func() {
			mockec2Client.EXPECT().
				DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					Expect(input.InstanceIds).To(ConsistOf(instanceID))
					return &ec2.DescribeInstancesOutput{
						Reservations: []types.Reservation{},
					}, nil
				})

			status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
			Expect(status).To(MatchFields(IgnoreExtras, Fields{
				"State":      Equal(v1alpha1.FirewallRuleStatePending),
				"Conditions": BeNil(),
			}))
			Expect(err).To(MatchError(&provider.Error{
				Code: "NotFoundError",
				Msg:  fmt.Sprintf("failed to get instance: instance with instance-id %s not found", instanceID),
			}))
		})

		It("should return a pending state and an error when an AWS API call (DescribeSecurityGroups) fails", func() {
			mockec2Client.EXPECT().
				DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					Expect(input.InstanceIds).To(ConsistOf(instanceID))
					return &ec2.DescribeInstancesOutput{
						Reservations: []types.Reservation{
							{
								Instances: []types.Instance{
									{
										InstanceId: aws.String(instanceID),
										VpcId:      aws.String(vpcID),
										NetworkInterfaces: []types.InstanceNetworkInterface{
											{
												Association: &types.InstanceNetworkInterfaceAssociation{
													IpOwnerId: aws.String("aws"),
													PublicIp:  aws.String(publicIP),
												},
												NetworkInterfaceId: aws.String(eniID),
											},
										},
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{}, fmt.Errorf("describe security groups error")
				})

			status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
			Expect(status).To(MatchFields(IgnoreExtras, Fields{
				"State": Equal(v1alpha1.FirewallRuleStatePending),
				"Conditions": HaveExactElements(matchCondition(
					kmetav1.Condition{
						Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
						Status: kmetav1.ConditionUnknown,
						Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
			}))
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to list security groups: describe security groups error",
			}))
		})

		When("the security group is not found", func() {
			It("should return a pending state if deletions timestamp is not nil (do nothing, deletion is pending)", func() {
				firewallRule.DeletionTimestamp = &kmetav1.Time{Time: time.Now()}
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{}, nil
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State":      Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": BeNil(),
				}))
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return a pending state and an error when an AWS API call (CreateSecurityGroup) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{}, nil
					})
				mockec2Client.EXPECT().
					CreateSecurityGroup(ctx, gomock.AssignableToTypeOf(&ec2.CreateSecurityGroupInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.CreateSecurityGroupInput, _ ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error) {
						Expect(input.VpcId).To(PointTo(Equal(vpcID)))
						Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
							"ResourceType": Equal(types.ResourceTypeSecurityGroup),
							"Tags":         ConsistOf(tags),
						})))
						return &ec2.CreateSecurityGroupOutput{}, fmt.Errorf("create security group error")
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchCondition(
						kmetav1.Condition{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to create security group: create security group error",
				}))
			})

			It("should return a pending state and an error when an AWS API call (DescribeSecurityGroups after security group creation) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							append(
								filters,
								types.Filter{
									Name:   aws.String("group-id"),
									Values: []string{securityGroupID},
								},
							),
						))
						return &ec2.DescribeSecurityGroupsOutput{}, fmt.Errorf("describe security groups error")
					})
				mockec2Client.EXPECT().
					CreateSecurityGroup(ctx, gomock.AssignableToTypeOf(&ec2.CreateSecurityGroupInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.CreateSecurityGroupInput, _ ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error) {
						Expect(input.VpcId).To(PointTo(Equal(vpcID)))
						Expect(input.TagSpecifications).To(ConsistOf(MatchFields(IgnoreExtras, Fields{
							"ResourceType": Equal(types.ResourceTypeSecurityGroup),
							"Tags":         ConsistOf(tags),
						})))
						return &ec2.CreateSecurityGroupOutput{
							GroupId: aws.String(securityGroupID),
						}, nil
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionUnknown,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to list security groups: describe security groups error",
				}))
			})
		})

		It("should return a pending state and an error when the instance has no public IP", func() {
			mockec2Client.EXPECT().
				DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					Expect(input.InstanceIds).To(ConsistOf(instanceID))
					return &ec2.DescribeInstancesOutput{
						Reservations: []types.Reservation{
							{
								Instances: []types.Instance{
									{
										InstanceId: aws.String(instanceID),
										VpcId:      aws.String(vpcID),
										NetworkInterfaces: []types.InstanceNetworkInterface{
											{
												Association: &types.InstanceNetworkInterfaceAssociation{
													IpOwnerId: aws.String("aws"),
												},
												NetworkInterfaceId: aws.String(eniID),
											},
										},
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId: aws.String(securityGroupID),
							},
						},
					}, nil
				})

			status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
			Expect(status).To(MatchFields(IgnoreExtras, Fields{
				"State": Equal(v1alpha1.FirewallRuleStatePending),
				"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
					{
						Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
						Status: kmetav1.ConditionTrue,
						Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
					},
					{
						Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
						Status: kmetav1.ConditionUnknown,
						Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
					},
				}, "LastTransitionTime", "ObservedGeneration", "Message")),
			}))
			Expect(err).To(MatchError(ContainSubstring("no network interface with public IP found")))
		})

		It("should return a pending state and an error when an AWS API call (DescribeNetworkInterfaces) fails", func() {
			mockec2Client.EXPECT().
				DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					Expect(input.InstanceIds).To(ConsistOf(instanceID))
					return &ec2.DescribeInstancesOutput{
						Reservations: []types.Reservation{
							{
								Instances: []types.Instance{
									{
										InstanceId: aws.String(instanceID),
										VpcId:      aws.String(vpcID),
										NetworkInterfaces: []types.InstanceNetworkInterface{
											{
												Association: &types.InstanceNetworkInterfaceAssociation{
													IpOwnerId: aws.String("aws"),
													PublicIp:  aws.String(publicIP),
												},
												NetworkInterfaceId: aws.String(eniID),
											},
										},
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId: aws.String(securityGroupID),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
					Expect(input.Filters).To(ConsistOf(
						types.Filter{
							Name:   aws.String("group-id"),
							Values: []string{securityGroupID},
						},
					))
					return &ec2.DescribeNetworkInterfacesOutput{}, fmt.Errorf("describe network interfaces error")
				})

			status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
			Expect(status).To(MatchFields(IgnoreExtras, Fields{
				"State": Equal(v1alpha1.FirewallRuleStatePending),
				"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
					{
						Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
						Status: kmetav1.ConditionTrue,
						Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
					},
					{
						Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
						Status: kmetav1.ConditionUnknown,
						Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
					},
				}, "LastTransitionTime", "ObservedGeneration", "Message")),
			}))
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to list network interfaces: describe network interfaces error",
			}))
		})

		It("should return a pending state and an error when an AWS API call (DescribeNetworkInterfaces) fails", func() {
			mockec2Client.EXPECT().
				DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					Expect(input.InstanceIds).To(ConsistOf(instanceID))
					return &ec2.DescribeInstancesOutput{
						Reservations: []types.Reservation{
							{
								Instances: []types.Instance{
									{
										InstanceId: aws.String(instanceID),
										VpcId:      aws.String(vpcID),
										NetworkInterfaces: []types.InstanceNetworkInterface{
											{
												Association: &types.InstanceNetworkInterfaceAssociation{
													IpOwnerId: aws.String("aws"),
													PublicIp:  aws.String(publicIP),
												},
												NetworkInterfaceId: aws.String(eniID),
											},
										},
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId: aws.String(securityGroupID),
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
					Expect(input.Filters).To(ConsistOf(
						types.Filter{
							Name:   aws.String("group-id"),
							Values: []string{securityGroupID},
						},
					))
					return &ec2.DescribeNetworkInterfacesOutput{}, fmt.Errorf("describe network interfaces error")
				})

			status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
			Expect(status).To(MatchFields(IgnoreExtras, Fields{
				"State": Equal(v1alpha1.FirewallRuleStatePending),
				"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
					{
						Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
						Status: kmetav1.ConditionTrue,
						Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
					},
					{
						Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
						Status: kmetav1.ConditionUnknown,
						Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
					},
				}, "LastTransitionTime", "ObservedGeneration", "Message")),
			}))
			Expect(err).To(MatchError(&provider.Error{
				Code: "InternalError",
				Msg:  "failed to list network interfaces: describe network interfaces error",
			}))
		})

		When("the instance's networkInterfaces is not empty and an ENI is already associated with the security group", func() {
			It("should return a pending state and an error when an AWS API call (ModifyNetworkInterfaceAttribute) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{
							NetworkInterfaces: []types.NetworkInterface{
								{
									NetworkInterfaceId: aws.String(eniID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
									},
								},
								{
									NetworkInterfaceId: aws.String(eni01ID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
										{
											GroupId: aws.String(securityGroup01ID),
										},
									},
								},
								{
									NetworkInterfaceId: aws.String(eni02ID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
										{
											GroupId: aws.String(securityGroup01ID),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
						Expect(input.NetworkInterfaceId).To(PointTo(Equal(eni01ID)))
						Expect(input.Groups).To(ConsistOf(securityGroup01ID))
						return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
					})
				mockec2Client.EXPECT().
					ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
						Expect(input.NetworkInterfaceId).To(PointTo(Equal(eni02ID)))
						Expect(input.Groups).To(ConsistOf(securityGroup01ID))
						return &ec2.ModifyNetworkInterfaceAttributeOutput{}, fmt.Errorf("modify network interface attribute error")
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to modify network interface attribute: modify network interface attribute error",
				}))
			})
		})

		When("the security group is not associated with the instance's network interfaces", func() {
			It("should return a pending state and an error when an AWS API call (ModifyNetworkInterfaceAttribute) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
														{
															GroupId: aws.String(securityGroup01ID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{}, nil
					})
				mockec2Client.EXPECT().
					ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
						Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
						Expect(input.Groups).To(ConsistOf(securityGroupID, securityGroup01ID))
						return &ec2.ModifyNetworkInterfaceAttributeOutput{}, fmt.Errorf("modify network interface attribute error")
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to modify network interface attribute: modify network interface attribute error",
				}))
			})

			It("should return a pending state and an error when an AWS API call (revokeSecurityGroupIngress) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
														{
															GroupId: aws.String(securityGroup01ID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
									IpPermissions: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5936),
											ToPort:     aws.Int32(5936),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{}, nil
					})
				mockec2Client.EXPECT().
					ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
						Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
						Expect(input.Groups).To(ConsistOf(securityGroupID, securityGroup01ID))
						return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
					})
				mockec2Client.EXPECT().
					RevokeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupIngressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5936),
								ToPort:     aws.Int32(5936),
								IpRanges:   []types.IpRange{},
							},
						))
						return &ec2.RevokeSecurityGroupIngressOutput{}, fmt.Errorf("revoke security group ingress error")
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to revoke security group ingress permission: revoke security group ingress error",
				}))
			})

			It("should return a pending state and an error when an AWS API call (revokeSecurityGroupEgress) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
														{
															GroupId: aws.String(securityGroup01ID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
									IpPermissions: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5936),
											ToPort:     aws.Int32(5936),
										},
									},
									IpPermissionsEgress: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5937),
											ToPort:     aws.Int32(5937),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{}, nil
					})
				mockec2Client.EXPECT().
					ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
						Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
						Expect(input.Groups).To(ConsistOf(securityGroupID, securityGroup01ID))
						return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
					})
				mockec2Client.EXPECT().
					RevokeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupIngressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5936),
								ToPort:     aws.Int32(5936),
								IpRanges:   []types.IpRange{},
							},
						))
						return &ec2.RevokeSecurityGroupIngressOutput{}, nil
					})
				mockec2Client.EXPECT().
					RevokeSecurityGroupEgress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupEgressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupEgressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5937),
								ToPort:     aws.Int32(5937),
								IpRanges:   []types.IpRange{},
							},
						))
						return &ec2.RevokeSecurityGroupEgressOutput{}, fmt.Errorf("revoke security group egress error")
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to revoke security group egress permission: revoke security group egress error",
				}))
			})
		})

		When("the firewallrule has a deletion timestamp", func() {
			BeforeEach(func() {
				firewallRule.DeletionTimestamp = &kmetav1.Time{Time: time.Now()}
			})

			When("the firewallrule is an ingress rule and the last rule", func() {
				It("should return an error when ReconcileFirewallRulesDeletion fails", func() {
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												VpcId:      aws.String(vpcID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eniID),
														Groups: []types.GroupIdentifier{
															{
																GroupId: aws.String(securityGroupID),
															},
														},
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeSecurityGroupsOutput{
								SecurityGroups: []types.SecurityGroup{
									{
										GroupId: aws.String(securityGroupID),
										IpPermissions: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5969),
												ToPort:     aws.Int32(5969),
												IpRanges: []types.IpRange{
													{
														CidrIp:      aws.String("0.0.0.0/0"),
														Description: aws.String(""),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								types.Filter{
									Name:   aws.String("group-id"),
									Values: []string{securityGroupID},
								},
							))
							return &ec2.DescribeNetworkInterfacesOutput{
								NetworkInterfaces: []types.NetworkInterface{
									{
										NetworkInterfaceId: aws.String(eniID),
										Groups: []types.GroupIdentifier{
											{
												GroupId: aws.String(securityGroupID),
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
							Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
							Expect(input.Groups).To(BeEmpty())
							return &ec2.ModifyNetworkInterfaceAttributeOutput{}, fmt.Errorf("modify network interface attribute error")

						})

					status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.FirewallRuleStatePending),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
							},
							{
								Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to modify network interface attribute: modify network interface attribute error",
					}))
				})
			})

			When("the firewallrule is an ingress rule and not the last rule (has at least another ingress rule)", func() {
				It("should return an error when an AWS API call (RevokeSecurityGroupIngress) fails", func() {
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												VpcId:      aws.String(vpcID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eniID),
														Groups: []types.GroupIdentifier{
															{
																GroupId: aws.String(securityGroupID),
															},
														},
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeSecurityGroupsOutput{
								SecurityGroups: []types.SecurityGroup{
									{
										GroupId: aws.String(securityGroupID),
										IpPermissions: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5969),
												ToPort:     aws.Int32(5969),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5970),
												ToPort:     aws.Int32(5970),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								types.Filter{
									Name:   aws.String("group-id"),
									Values: []string{securityGroupID},
								},
							))
							return &ec2.DescribeNetworkInterfacesOutput{
								NetworkInterfaces: []types.NetworkInterface{
									{
										NetworkInterfaceId: aws.String(eniID),
										Groups: []types.GroupIdentifier{
											{
												GroupId: aws.String(securityGroupID),
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						RevokeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupIngressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
							Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
							Expect(input.IpPermissions).To(ConsistOf(
								types.IpPermission{
									IpProtocol: aws.String("TCP"),
									FromPort:   aws.Int32(5969),
									ToPort:     aws.Int32(5969),
									IpRanges: []types.IpRange{
										{
											CidrIp: aws.String("0.0.0.0/0"),
										},
									},
								},
							))
							return &ec2.RevokeSecurityGroupIngressOutput{}, fmt.Errorf("revoke security group ingress error")
						})

					status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.FirewallRuleStatePending),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
							},
							{
								Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to revoke security group ingress permission: revoke security group ingress error",
					}))
				})
			})

			When("the firewallrule is an ingress rule and not the last rule (has at least another egress rule)", func() {
				BeforeEach(func() {
					firewallRule01.Spec.Direction = v1alpha1.DirectionEgress
					firewallrules = []v1alpha1.FirewallRule{*firewallRule, *firewallRule01}
				})
				It("should return an error when an AWS API call (RevokeSecurityGroupIngress) fails", func() {
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												VpcId:      aws.String(vpcID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eniID),
														Groups: []types.GroupIdentifier{
															{
																GroupId: aws.String(securityGroupID),
															},
														},
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeSecurityGroupsOutput{
								SecurityGroups: []types.SecurityGroup{
									{
										GroupId: aws.String(securityGroupID),
										IpPermissions: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5969),
												ToPort:     aws.Int32(5969),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
										},
										IpPermissionsEgress: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5970),
												ToPort:     aws.Int32(5970),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								types.Filter{
									Name:   aws.String("group-id"),
									Values: []string{securityGroupID},
								},
							))
							return &ec2.DescribeNetworkInterfacesOutput{
								NetworkInterfaces: []types.NetworkInterface{
									{
										NetworkInterfaceId: aws.String(eniID),
										Groups: []types.GroupIdentifier{
											{
												GroupId: aws.String(securityGroupID),
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						RevokeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupIngressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
							Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
							Expect(input.IpPermissions).To(ConsistOf(
								types.IpPermission{
									IpProtocol: aws.String("TCP"),
									FromPort:   aws.Int32(5969),
									ToPort:     aws.Int32(5969),
									IpRanges: []types.IpRange{
										{
											CidrIp: aws.String("0.0.0.0/0"),
										},
									},
								},
							))
							return &ec2.RevokeSecurityGroupIngressOutput{}, fmt.Errorf("revoke security group ingress error")
						})

					status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.FirewallRuleStatePending),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
							},
							{
								Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to revoke security group ingress permission: revoke security group ingress error",
					}))
				})
			})

			When("the firewallrule is an egress rule and the last rule", func() {
				BeforeEach(func() {
					firewallRule.Spec.Direction = v1alpha1.DirectionEgress
					firewallrules = []v1alpha1.FirewallRule{*firewallRule, *firewallRule01}
				})
				It("should return an error when ReconcileFirewallRulesDeletion fails", func() {
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												VpcId:      aws.String(vpcID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eniID),
														Groups: []types.GroupIdentifier{
															{
																GroupId: aws.String(securityGroupID),
															},
														},
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeSecurityGroupsOutput{
								SecurityGroups: []types.SecurityGroup{
									{
										GroupId: aws.String(securityGroupID),
										IpPermissionsEgress: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5969),
												ToPort:     aws.Int32(5969),
												IpRanges: []types.IpRange{
													{
														CidrIp:      aws.String("0.0.0.0/0"),
														Description: aws.String(""),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								types.Filter{
									Name:   aws.String("group-id"),
									Values: []string{securityGroupID},
								},
							))
							return &ec2.DescribeNetworkInterfacesOutput{
								NetworkInterfaces: []types.NetworkInterface{
									{
										NetworkInterfaceId: aws.String(eniID),
										Groups: []types.GroupIdentifier{
											{
												GroupId: aws.String(securityGroupID),
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						ModifyNetworkInterfaceAttribute(ctx, gomock.AssignableToTypeOf(&ec2.ModifyNetworkInterfaceAttributeInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.ModifyNetworkInterfaceAttributeInput, _ ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
							Expect(input.NetworkInterfaceId).To(PointTo(Equal(eniID)))
							Expect(input.Groups).To(BeEmpty())
							return &ec2.ModifyNetworkInterfaceAttributeOutput{}, fmt.Errorf("modify network interface attribute error")

						})

					status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.FirewallRuleStatePending),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
							},
							{
								Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to modify network interface attribute: modify network interface attribute error",
					}))
				})
			})

			When("the firewallrule is an egress rule and not the last rule (has at least another egress rule)", func() {
				BeforeEach(func() {
					firewallRule.Spec.Direction = v1alpha1.DirectionEgress
					firewallRule01.Spec.Direction = v1alpha1.DirectionEgress
					firewallrules = []v1alpha1.FirewallRule{*firewallRule, *firewallRule01}
				})
				It("should return an error when an AWS API call (RevokeSecurityGroupEgress) fails", func() {
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												VpcId:      aws.String(vpcID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eniID),
														Groups: []types.GroupIdentifier{
															{
																GroupId: aws.String(securityGroupID),
															},
														},
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeSecurityGroupsOutput{
								SecurityGroups: []types.SecurityGroup{
									{
										GroupId: aws.String(securityGroupID),
										IpPermissionsEgress: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5969),
												ToPort:     aws.Int32(5969),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5970),
												ToPort:     aws.Int32(5970),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								types.Filter{
									Name:   aws.String("group-id"),
									Values: []string{securityGroupID},
								},
							))
							return &ec2.DescribeNetworkInterfacesOutput{
								NetworkInterfaces: []types.NetworkInterface{
									{
										NetworkInterfaceId: aws.String(eniID),
										Groups: []types.GroupIdentifier{
											{
												GroupId: aws.String(securityGroupID),
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						RevokeSecurityGroupEgress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupEgressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupEgressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
							Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
							Expect(input.IpPermissions).To(ConsistOf(
								types.IpPermission{
									IpProtocol: aws.String("TCP"),
									FromPort:   aws.Int32(5969),
									ToPort:     aws.Int32(5969),
									IpRanges: []types.IpRange{
										{
											CidrIp: aws.String("0.0.0.0/0"),
										},
									},
								},
							))
							return &ec2.RevokeSecurityGroupEgressOutput{}, fmt.Errorf("revoke security group egress error")
						})

					status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.FirewallRuleStatePending),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
							},
							{
								Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to revoke security group egress permission: revoke security group egress error",
					}))
				})
			})

			When("the firewallrule is an egress rule and not the last rule (has at least another ingress rule)", func() {
				BeforeEach(func() {
					firewallRule.Spec.Direction = v1alpha1.DirectionEgress
					firewallrules = []v1alpha1.FirewallRule{*firewallRule, *firewallRule01}
				})
				It("should return an error when an AWS API call (RevokeSecurityGroupEgress) fails", func() {
					mockec2Client.EXPECT().
						DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
							Expect(input.InstanceIds).To(ConsistOf(instanceID))
							return &ec2.DescribeInstancesOutput{
								Reservations: []types.Reservation{
									{
										Instances: []types.Instance{
											{
												InstanceId: aws.String(instanceID),
												VpcId:      aws.String(vpcID),
												NetworkInterfaces: []types.InstanceNetworkInterface{
													{
														Association: &types.InstanceNetworkInterfaceAssociation{
															IpOwnerId: aws.String("aws"),
															PublicIp:  aws.String(publicIP),
														},
														NetworkInterfaceId: aws.String(eniID),
														Groups: []types.GroupIdentifier{
															{
																GroupId: aws.String(securityGroupID),
															},
														},
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
							Expect(input.Filters).To(ConsistOf(filters))
							return &ec2.DescribeSecurityGroupsOutput{
								SecurityGroups: []types.SecurityGroup{
									{
										GroupId: aws.String(securityGroupID),
										IpPermissionsEgress: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5969),
												ToPort:     aws.Int32(5969),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
										},
										IpPermissions: []types.IpPermission{
											{
												IpProtocol: aws.String("TCP"),
												FromPort:   aws.Int32(5970),
												ToPort:     aws.Int32(5970),
												IpRanges: []types.IpRange{
													{
														CidrIp: aws.String("0.0.0.0/0"),
													},
												},
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
							Expect(input.Filters).To(ConsistOf(
								types.Filter{
									Name:   aws.String("group-id"),
									Values: []string{securityGroupID},
								},
							))
							return &ec2.DescribeNetworkInterfacesOutput{
								NetworkInterfaces: []types.NetworkInterface{
									{
										NetworkInterfaceId: aws.String(eniID),
										Groups: []types.GroupIdentifier{
											{
												GroupId: aws.String(securityGroupID),
											},
										},
									},
								},
							}, nil
						})
					mockec2Client.EXPECT().
						RevokeSecurityGroupEgress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupEgressInput{})).
						DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupEgressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
							Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
							Expect(input.IpPermissions).To(ConsistOf(
								types.IpPermission{
									IpProtocol: aws.String("TCP"),
									FromPort:   aws.Int32(5969),
									ToPort:     aws.Int32(5969),
									IpRanges: []types.IpRange{
										{
											CidrIp: aws.String("0.0.0.0/0"),
										},
									},
								},
							))
							return &ec2.RevokeSecurityGroupEgressOutput{}, fmt.Errorf("revoke security group Egress error")
						})

					status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
					Expect(status).To(MatchFields(IgnoreExtras, Fields{
						"State": Equal(v1alpha1.FirewallRuleStatePending),
						"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
							{
								Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
							},
							{
								Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
								Status: kmetav1.ConditionTrue,
								Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
							},
						}, "LastTransitionTime", "ObservedGeneration", "Message")),
					}))
					Expect(err).To(MatchError(&provider.Error{
						Code: "InternalError",
						Msg:  "failed to revoke security group egress permission: revoke security group Egress error",
					}))
				})
			})

			It("should return a status and nil when it succeeds", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
									IpPermissions: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5969),
											ToPort:     aws.Int32(5969),
											IpRanges: []types.IpRange{
												{
													CidrIp: aws.String("0.0.0.0/0"),
												},
											},
										},
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5970),
											ToPort:     aws.Int32(5970),
											IpRanges: []types.IpRange{
												{
													CidrIp: aws.String("0.0.0.0/0"),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{
							NetworkInterfaces: []types.NetworkInterface{
								{
									NetworkInterfaceId: aws.String(eniID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					RevokeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.RevokeSecurityGroupIngressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(aws.ToString(&securityGroupID))))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5969),
								ToPort:     aws.Int32(5969),
								IpRanges: []types.IpRange{
									{
										CidrIp: aws.String("0.0.0.0/0"),
									},
								},
							},
						))
						return &ec2.RevokeSecurityGroupIngressOutput{}, nil
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).ToNot(HaveOccurred())
			})
		})

		When("the firewallrule is an ingress rule", func() {
			It("should return a pending state, specify in the condition when the maximum rule is reached and an error when an AWS API call  (AuthorizeSecurityGroupIngress) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
									IpPermissions: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5970),
											ToPort:     aws.Int32(5970),
											IpRanges: []types.IpRange{
												{
													CidrIp:      aws.String("0.0.0.0/0"),
													Description: aws.String(""),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{
							NetworkInterfaces: []types.NetworkInterface{
								{
									NetworkInterfaceId: aws.String(eniID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					AuthorizeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.AuthorizeSecurityGroupIngressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AuthorizeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(securityGroupID)))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5969),
								ToPort:     aws.Int32(5969),
								IpRanges: []types.IpRange{
									{
										CidrIp: aws.String("0.0.0.0/0"),
									},
								},
							},
						))
						return &ec2.AuthorizeSecurityGroupIngressOutput{}, &smithy.GenericAPIError{
							Code:    "RulesPerSecurityGroupLimitExceeded",
							Message: "Too many rules added to the security group",
							Fault:   smithy.FaultClient,
						}
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "RulesPerSecurityGroupLimitExceeded",
					Msg:  "failed to authorize security group ingress permission: api error RulesPerSecurityGroupLimitExceeded: Too many rules added to the security group",
				}))
			})

			It("should return a pending state and an error when an AWS API call (AuthorizeSecurityGroupIngress) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
									IpPermissions: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5970),
											ToPort:     aws.Int32(5970),
											IpRanges: []types.IpRange{
												{
													CidrIp:      aws.String("0.0.0.0/0"),
													Description: aws.String(""),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{
							NetworkInterfaces: []types.NetworkInterface{
								{
									NetworkInterfaceId: aws.String(eniID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					AuthorizeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.AuthorizeSecurityGroupIngressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AuthorizeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(securityGroupID)))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5969),
								ToPort:     aws.Int32(5969),
								IpRanges: []types.IpRange{
									{
										CidrIp: aws.String("0.0.0.0/0"),
									},
								},
							},
						))
						return &ec2.AuthorizeSecurityGroupIngressOutput{}, fmt.Errorf("authorize security group ingress error")
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to authorize security group ingress permission: authorize security group ingress error",
				}))
			})
		})

		When("the firewallrule is an egress rule", func() {
			BeforeEach(func() {
				firewallRule.Spec.Direction = v1alpha1.DirectionEgress
				firewallrules = []v1alpha1.FirewallRule{*firewallRule, *firewallRule01}
			})
			It("should return a pending state, specify in the condition when the maximum rule is reached and an error when an AWS API call  (AuthorizeSecurityGroupIngress) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
									IpPermissions: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5970),
											ToPort:     aws.Int32(5970),
											IpRanges: []types.IpRange{
												{
													CidrIp:      aws.String("0.0.0.0/0"),
													Description: aws.String(""),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{
							NetworkInterfaces: []types.NetworkInterface{
								{
									NetworkInterfaceId: aws.String(eniID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					AuthorizeSecurityGroupEgress(ctx, gomock.AssignableToTypeOf(&ec2.AuthorizeSecurityGroupEgressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AuthorizeSecurityGroupEgressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(securityGroupID)))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5969),
								ToPort:     aws.Int32(5969),
								IpRanges: []types.IpRange{
									{
										CidrIp: aws.String("0.0.0.0/0"),
									},
								},
							},
						))
						return &ec2.AuthorizeSecurityGroupEgressOutput{}, &smithy.GenericAPIError{
							Code:    "RulesPerSecurityGroupLimitExceeded",
							Message: "Too many rules added to the security group",
							Fault:   smithy.FaultClient,
						}
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "RulesPerSecurityGroupLimitExceeded",
					Msg:  "failed to authorize security group egress permission: api error RulesPerSecurityGroupLimitExceeded: Too many rules added to the security group",
				}))
			})

			It("should return a pending state and an error when an AWS API call (AuthorizeSecurityGroupEgress) fails", func() {
				mockec2Client.EXPECT().
					DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
						Expect(input.InstanceIds).To(ConsistOf(instanceID))
						return &ec2.DescribeInstancesOutput{
							Reservations: []types.Reservation{
								{
									Instances: []types.Instance{
										{
											InstanceId: aws.String(instanceID),
											VpcId:      aws.String(vpcID),
											NetworkInterfaces: []types.InstanceNetworkInterface{
												{
													Association: &types.InstanceNetworkInterfaceAssociation{
														IpOwnerId: aws.String("aws"),
														PublicIp:  aws.String(publicIP),
													},
													NetworkInterfaceId: aws.String(eniID),
													Groups: []types.GroupIdentifier{
														{
															GroupId: aws.String(securityGroupID),
														},
													},
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
						Expect(input.Filters).To(ConsistOf(filters))
						return &ec2.DescribeSecurityGroupsOutput{
							SecurityGroups: []types.SecurityGroup{
								{
									GroupId: aws.String(securityGroupID),
									IpPermissions: []types.IpPermission{
										{
											IpProtocol: aws.String("TCP"),
											FromPort:   aws.Int32(5970),
											ToPort:     aws.Int32(5970),
											IpRanges: []types.IpRange{
												{
													CidrIp:      aws.String("0.0.0.0/0"),
													Description: aws.String(""),
												},
											},
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
						Expect(input.Filters).To(ConsistOf(
							types.Filter{
								Name:   aws.String("group-id"),
								Values: []string{securityGroupID},
							},
						))
						return &ec2.DescribeNetworkInterfacesOutput{
							NetworkInterfaces: []types.NetworkInterface{
								{
									NetworkInterfaceId: aws.String(eniID),
									Groups: []types.GroupIdentifier{
										{
											GroupId: aws.String(securityGroupID),
										},
									},
								},
							},
						}, nil
					})
				mockec2Client.EXPECT().
					AuthorizeSecurityGroupEgress(ctx, gomock.AssignableToTypeOf(&ec2.AuthorizeSecurityGroupEgressInput{})).
					DoAndReturn(func(_ context.Context, input *ec2.AuthorizeSecurityGroupEgressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
						Expect(input.GroupId).To(PointTo(Equal(securityGroupID)))
						Expect(input.IpPermissions).To(ConsistOf(
							types.IpPermission{
								IpProtocol: aws.String("TCP"),
								FromPort:   aws.Int32(5969),
								ToPort:     aws.Int32(5969),
								IpRanges: []types.IpRange{
									{
										CidrIp: aws.String("0.0.0.0/0"),
									},
								},
							},
						))
						return &ec2.AuthorizeSecurityGroupEgressOutput{}, fmt.Errorf("authorize security group egress error")
					})

				status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
				Expect(status).To(MatchFields(IgnoreExtras, Fields{
					"State": Equal(v1alpha1.FirewallRuleStatePending),
					"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
							Status: kmetav1.ConditionTrue,
							Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
						},
						{
							Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
							Status: kmetav1.ConditionFalse,
							Reason: v1alpha1.FirewallRuleConditionReasonProviderError,
						},
					}, "LastTransitionTime", "ObservedGeneration", "Message")),
				}))
				Expect(err).To(MatchError(&provider.Error{
					Code: "InternalError",
					Msg:  "failed to authorize security group egress permission: authorize security group egress error",
				}))
			})
		})

		It("should return an applied status when the firewallRule is added without error", func() {
			mockec2Client.EXPECT().
				DescribeInstances(ctx, gomock.AssignableToTypeOf(&ec2.DescribeInstancesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					Expect(input.InstanceIds).To(ConsistOf(instanceID))
					return &ec2.DescribeInstancesOutput{
						Reservations: []types.Reservation{
							{
								Instances: []types.Instance{
									{
										InstanceId: aws.String(instanceID),
										VpcId:      aws.String(vpcID),
										NetworkInterfaces: []types.InstanceNetworkInterface{
											{
												Association: &types.InstanceNetworkInterfaceAssociation{
													IpOwnerId: aws.String("aws"),
													PublicIp:  aws.String(publicIP),
												},
												NetworkInterfaceId: aws.String(eniID),
												Groups: []types.GroupIdentifier{
													{
														GroupId: aws.String(securityGroupID),
													},
												},
											},
										},
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeSecurityGroups(ctx, gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					Expect(input.Filters).To(ConsistOf(filters))
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []types.SecurityGroup{
							{
								GroupId: aws.String(securityGroupID),
								IpPermissions: []types.IpPermission{
									{
										IpProtocol: aws.String("TCP"),
										FromPort:   aws.Int32(5970),
										ToPort:     aws.Int32(5970),
										IpRanges: []types.IpRange{
											{
												CidrIp:      aws.String("0.0.0.0/0"),
												Description: aws.String(""),
											},
										},
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				DescribeNetworkInterfaces(ctx, gomock.AssignableToTypeOf(&ec2.DescribeNetworkInterfacesInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
					Expect(input.Filters).To(ConsistOf(
						types.Filter{
							Name:   aws.String("group-id"),
							Values: []string{securityGroupID},
						},
					))
					return &ec2.DescribeNetworkInterfacesOutput{
						NetworkInterfaces: []types.NetworkInterface{
							{
								NetworkInterfaceId: aws.String(eniID),
								Groups: []types.GroupIdentifier{
									{
										GroupId: aws.String(securityGroupID),
									},
								},
							},
						},
					}, nil
				})
			mockec2Client.EXPECT().
				AuthorizeSecurityGroupIngress(ctx, gomock.AssignableToTypeOf(&ec2.AuthorizeSecurityGroupIngressInput{})).
				DoAndReturn(func(_ context.Context, input *ec2.AuthorizeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
					Expect(input.GroupId).To(PointTo(Equal(securityGroupID)))
					Expect(input.IpPermissions).To(ConsistOf(
						types.IpPermission{
							IpProtocol: aws.String("TCP"),
							FromPort:   aws.Int32(5969),
							ToPort:     aws.Int32(5969),
							IpRanges: []types.IpRange{
								{
									CidrIp: aws.String("0.0.0.0/0"),
								},
							},
						},
					))
					return &ec2.AuthorizeSecurityGroupIngressOutput{}, nil
				})

			status, err := p.ReconcileFirewallRule(ctx, log, nodeName, instanceID, firewallRule, firewallrules)
			Expect(status).To(MatchFields(IgnoreExtras, Fields{
				"State": Equal(v1alpha1.FirewallRuleStateApplied),
				"Conditions": HaveExactElements(matchConditions([]kmetav1.Condition{
					{
						Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
						Status: kmetav1.ConditionTrue,
						Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
					},
					{
						Type:   v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
						Status: kmetav1.ConditionTrue,
						Reason: v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
					},
					{
						Type:   v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
						Status: kmetav1.ConditionTrue,
						Reason: v1alpha1.FirewallRuleConditionReasonSecurityGroupRuleAuthorized,
					},
				}, "LastTransitionTime", "ObservedGeneration", "Message")),
			}))
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

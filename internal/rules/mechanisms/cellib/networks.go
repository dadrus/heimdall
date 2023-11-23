package cellib

import (
	"fmt"
	"net"
	"reflect"
	"slices"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/yl2chen/cidranger"
)

//nolint:gochecknoglobals
var ipNetworksType = cel.ObjectType(reflect.TypeOf(IPNetworks{}).String(), traits.ReceiverType|traits.ContainerType)

func newIPNetworks(cidrs []string) (IPNetworks, error) {
	ranger := cidranger.NewPCTrieRanger()

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return IPNetworks{}, err
		}

		if err = ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet)); err != nil {
			return IPNetworks{}, err
		}
	}

	return IPNetworks{Ranger: ranger, cidrs: cidrs}, nil
}

type IPNetworks struct {
	cidranger.Ranger

	cidrs []string
}

func (n IPNetworks) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(n.Ranger).AssignableTo(typeDesc) {
		return n.Ranger, nil
	}

	if reflect.TypeOf(n).AssignableTo(typeDesc) {
		return n, nil
	}

	return nil, fmt.Errorf("%w: from 'networks' to '%v'", errTypeConversion, typeDesc)
}

func (n IPNetworks) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case ipNetworksType:
		return n
	case cel.TypeType:
		return ipNetworksType
	}

	return types.NewErr("type conversion error from 'networks' to '%s'", typeVal)
}

func (n IPNetworks) Equal(other ref.Val) ref.Val {
	otherDur, ok := other.(IPNetworks)

	return types.Bool(ok && n.Ranger == otherDur.Ranger)
}

func (n IPNetworks) Type() ref.Type {
	return ipNetworksType
}

func (n IPNetworks) Value() any {
	return n.Ranger
}

func (n IPNetworks) Contains(value ref.Val) ref.Val {
	if singleIP, ok := value.Value().(string); ok {
		return types.Bool(n.containsIP(singleIP))
	}

	if lister, ok := value.(traits.Lister); ok {
		ips, err := lister.ConvertToNative(reflect.TypeOf([]string{}))
		if err != nil {
			return types.WrapErr(err)
		}

		return types.Bool(n.containsAll(ips.([]string))) // nolint: forcetypeassert
	}

	return types.False
}

func (n IPNetworks) containsIP(ip string) bool {
	res, _ := n.Ranger.Contains(net.ParseIP(ip))

	return res
}

func (n IPNetworks) containsAll(ips []string) bool {
	for _, ip := range ips {
		if !n.containsIP(ip) {
			return false
		}
	}

	return true
}

func Networks() cel.EnvOption {
	return cel.Lib(networksLib{})
}

type networksLib struct{}

func (networksLib) LibraryName() string {
	return "dadrus.heimdall.networks"
}

func (networksLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (networksLib) CompileOptions() []cel.EnvOption {
	var networkInstances []IPNetworks

	return []cel.EnvOption{
		// IPNetworks specific functions
		cel.Function("networks",
			cel.Overload("networks_from_cidr",
				[]*cel.Type{cel.StringType}, ipNetworksType,
				cel.UnaryBinding(func(netVal ref.Val) ref.Val {
					addresses := []string{netVal.Value().(string)} // nolint: forcetypeassert

					for _, net := range networkInstances {
						if slices.Equal(net.cidrs, addresses) {
							return net
						}
					}

					networks, err := newIPNetworks(addresses)
					if err != nil {
						return types.WrapErr(err)
					}

					networkInstances = append(networkInstances, networks)

					return networks
				}),
			),
			cel.Overload("networks_from_cidr_array",
				[]*cel.Type{cel.ListType(cel.StringType)}, ipNetworksType,
				cel.UnaryBinding(func(netsVal ref.Val) ref.Val {
					cidrs, err := netsVal.ConvertToNative(reflect.TypeOf([]string{}))
					if err != nil {
						return types.WrapErr(err)
					}

					addresses := cidrs.([]string) // nolint: forcetypeassert
					slices.Sort(addresses)

					for _, net := range networkInstances {
						if slices.Equal(net.cidrs, addresses) {
							return net
						}
					}

					networks, err := newIPNetworks(addresses)
					if err != nil {
						return types.WrapErr(err)
					}

					networkInstances = append(networkInstances, networks)

					return networks
				}),
			),
		),
		cel.Function(operators.In,
			cel.Overload("ip_in_networks",
				[]*cel.Type{cel.StringType, ipNetworksType}, types.BoolType),
			cel.Overload("ips_in_networks",
				[]*cel.Type{cel.ListType(cel.StringType), ipNetworksType}, types.BoolType),
		),
	}
}

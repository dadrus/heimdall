package cellib

import (
	"fmt"
	"net"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
	"github.com/yl2chen/cidranger"
)

var (
	ipNetworkType  = cel.ObjectType(reflect.TypeOf(IPNetwork{}).String(), traits.ReceiverType|traits.ContainerType)  //nolint:gochecknoglobals
	ipNetworksType = cel.ObjectType(reflect.TypeOf(IPNetworks{}).String(), traits.ReceiverType|traits.ContainerType) //nolint:gochecknoglobals
)

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

	return IPNetworks{ranger}, nil
}

type IPNetworks struct {
	cidranger.Ranger
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

func newIPNetwork(cidr string) (IPNetwork, error) {
	_, ips, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPNetwork{}, err
	}

	return IPNetwork{ips}, nil
}

type IPNetwork struct {
	*net.IPNet
}

func (v IPNetwork) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(v.IPNet).AssignableTo(typeDesc) {
		return v.IPNet, nil
	}

	if reflect.TypeOf(v).AssignableTo(typeDesc) {
		return v, nil
	}

	return nil, fmt.Errorf("%w: from 'network' to '%v'", errTypeConversion, typeDesc)
}

func (v IPNetwork) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case ipNetworkType:
		return v
	case cel.TypeType:
		return ipNetworkType
	}

	return types.NewErr("type conversion error from '%s' to '%s'", ipNetworkType, typeVal)
}

func (v IPNetwork) Equal(other ref.Val) ref.Val {
	otherDur, ok := other.(IPNetwork)

	return types.Bool(ok && v.IPNet == otherDur.IPNet)
}

func (v IPNetwork) Type() ref.Type {
	return ipNetworkType
}

func (v IPNetwork) Value() any {
	return v.IPNet
}

func (v IPNetwork) Contains(value ref.Val) ref.Val {
	if singleIP, ok := value.Value().(string); ok {
		return types.Bool(v.containsIP(singleIP))
	}

	if lister, ok := value.(traits.Lister); ok {
		ips, err := lister.ConvertToNative(reflect.TypeOf([]string{}))
		if err != nil {
			return types.WrapErr(err)
		}

		return types.Bool(v.containsAll(ips.([]string))) // nolint: forcetypeassert
	}

	return types.False
}

func (v IPNetwork) containsIP(ip string) bool {
	return v.IPNet.Contains(net.ParseIP(ip))
}

func (v IPNetwork) containsAll(ips []string) bool {
	for _, ip := range ips {
		if !v.containsIP(ip) {
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

//nolint:funlen
func (networksLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		ext.NativeTypes(
			reflect.TypeOf(IPNetwork{}),
			reflect.TypeOf(IPNetworks{}),
		),
		// IPNetwork specific functions
		cel.Function("network",
			cel.Overload("network",
				[]*cel.Type{cel.StringType}, cel.DynType,
				cel.UnaryBinding(func(netVal ref.Val) ref.Val {
					network, err := newIPNetwork(netVal.Value().(string))
					if err != nil {
						return types.WrapErr(err)
					}

					return network
				}),
			),
		),
		cel.Function(operators.In,
			decls.Overload("ip_in_network",
				[]*cel.Type{cel.StringType, ipNetworkType}, types.BoolType),
			decls.Overload("ips_in_network",
				[]*cel.Type{cel.ListType(cel.StringType), ipNetworkType}, types.BoolType),
		),

		// IPNetworks specific functions
		cel.Function("networks",
			cel.Overload("networks",
				[]*cel.Type{cel.ListType(cel.StringType)}, cel.DynType,
				cel.UnaryBinding(func(netsVal ref.Val) ref.Val {
					cidrs, err := netsVal.ConvertToNative(reflect.TypeOf([]string{}))
					if err != nil {
						return types.WrapErr(err)
					}

					networks, err := newIPNetworks(cidrs.([]string))
					if err != nil {
						return types.WrapErr(err)
					}

					return networks
				}),
			),
		),
		cel.Function(operators.In,
			decls.Overload("ip_in_networks",
				[]*cel.Type{cel.StringType, ipNetworksType}, types.BoolType),
			decls.Overload("ips_in_networks",
				[]*cel.Type{cel.ListType(cel.StringType), ipNetworksType}, types.BoolType),
		),
	}
}

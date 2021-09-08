import os
import re
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Any, Union, Optional, Sequence, Dict

from mako.template import Template
from mako import exceptions as mako_exception

IN = 'in'
OUT = 'out'
IPV4 = 'ipv4'
IPV6 = 'ipv6'
PERMIT = 'permit'
DENY = 'deny'
ANY = 'any'
ALL = 'all'
NONE = 'none'


class UnsupportedOperation(Exception):
    pass


class AccessList(object):
    def __init__(self, name, af):
        assert (any(af == x for x in [IPV4, IPV6]))
        self.name = name
        self.af = af
        self.networks = list()

    def __eq__(self, other):
        if not isinstance(other, AccessList):
            return False
        return other.name == self.name

    def __hash__(self):
        return hash(self.name)

    def permit_all(self):
        self.networks.clear()
        self.networks.append((PERMIT, 'all'))

    def deny_all(self):
        self.networks.clear()
        self.networks.append((DENY, 'all'))

    def append(self, net, auth):
        #     self.af == IPv4 ==> net instanceof IPv4Network
        # AND self.af == IPv6 ==> net instanceof IPv6Network
        assert ((self.af != IPV4) or (isinstance(net, IPv4Network)) and
                (self.af != IPV6) or (isinstance(net, IPv6Network)))

        assert any(auth == x for x in [PERMIT, DENY])

        self.networks.append((auth, net))

    def is_v4(self):
        return self.af == IPV4

    def is_v6(self):
        return self.af == IPV6

    def to_str(self, bgp_implem):
        return bgp_implem.acl_list_str(self)


class Singleton(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__new__(
                cls, *args, **kwargs)
        return cls._instance


class BGPAttributeFlags(object):
    """
    Represents the flags part of a BGP attribute (RFC 4271 section 4.3)
    The flags are an 8-bits integer value in the form `O T P E 0 0 0 0`.
    When :
    * bit `O` is set to 0: the attribute is Well-Known. If 1, it is optional
    * bit `T` is set to 0: the attribute is not Transitive. If 1, it is transitive
    * bit `P` is set to 0: the attribute is complete; If 1, partial
    * bit `E` is set to 0: the attribute is of length < 256 bits. If set to 1: 256 <= length < 2^{16}
    The last 4 bits are unused
    This class is notably used to define new attributes unknown from ExaBGP or change
    the flags of a already known attribute. For example, the MED value is not transitive.
    To make it transitive, put the transitive bit to 1.
    """

    @staticmethod
    def to_hex_flags(a, b, c, d):
        return (((a << 3) & 8) | ((b << 2) & 4) | ((c << 1) & 2) | (d & 1)) << 4

    def __init__(self, optional, transitive, partial, extended):
        allowed_vals = {0, 1}
        assert optional in allowed_vals
        assert transitive in allowed_vals
        assert partial in allowed_vals
        assert extended in allowed_vals

        self.optional = optional
        self.transitive = transitive
        self.partial = partial
        self.extended = extended

        self._hex = self.to_hex_flags(self.optional, self.transitive, self.partial, self.extended)

    def __str__(self):
        return self.hex_repr()

    def hex_repr(self):
        return f"0X{self._hex:X}"

    def __repr__(self):
        return "BGPAttributeFlags(opt=%d, transitive=%d, partial=%d, ext=%d, _hex=%s (%s))" % (
            self.optional, self.transitive, self.partial, self.extended, hex(self._hex), bin(self._hex))


class BGPAttribute(object):
    """
    A BGP attribute as represented in ExaBGP. Either the Attribute is known from ExaBGP
    and so the class uses its string representation. Or the attribute is not known, then
    the class uses its hexadecimal representation. The latter representation is also useful
    to modify flags of already known attributes. For example the MED value is a known attribute
    which is not transitive. By passing a BGPAttributeFlags object to the constructor, it is
    now possible to make is transitive with BGPAttributeFlags(1, 1, 0, 0) (both optional and
    transitive bits are set to 1)
    """

    @property
    def _known_attr(self):
        return {'next-hop', 'origin', 'med',
                'as-path', 'local-preference', 'atomic-aggregate',
                'aggregator', 'originator-id', 'cluster-list',
                'community', 'large-community', 'extended-community',
                'name', 'aigp'}

    def hex_repr(self) -> str:
        return "attribute [ {type} {flags} {value} ]".format(
            type=hex(self.type),
            flags=self.flags.hex_repr(),
            value=self.val.hex_repr())

    def str_repr(self) -> str:
        if isinstance(self.val, str):
            # str isinstance of Sequence !
            # so must be at the very top
            str_val = self.val
        elif isinstance(self.val, Sequence):
            str_val = "[ {seq} ]".format(seq=" ".join([str(it) for it in self.val]))
        else:
            str_val = str(self.val)

        return "{type} {value}".format(type=str(self.type), value=str_val)

    def __init__(self, attr_type: Union[str, int], val: Union[int, str, list],
                 flags: Optional['BGPAttributeFlags'] = None):

        def is_hex_str(hex_str):
            if not isinstance(hex_str, str):
                return False
            return re.match(r"^(0[xX])?[A-Fa-f0-9]+$", hex_str) is not None

        """
        Constructs an Attribute known from ExaBGP or an unknown attribute if flags is
        not None. It raises a ValueError if the initialisation of BGPAttribute fails. Either because type_attr
        is not an int (for an unknown attribute), or the string of type_attr is not recognised
        by ExaBGP (for a known attribute)
        :param attr_type: In the case of a Known attribute, attr_type is a valid string
                          recognised by ExaBGP. In the case of an unknown attribute, attr_type is the integer
                          ID of the attribute. If attr_type is a string it must be a valid string recognized
                          by ExaBGP. Valid strings are:
                          'next-hop', 'origin', 'med', 'as-path', 'local-preference', 'atomic-aggregate',
                          'aggregator', 'originator-id', 'cluster-list','community', 'large-community',
                          'extended-community', 'name', 'aigp'
        :param val: The actual value of the attribute
        :param flags: If None, the BGPAttribute object contains a known attribute from ExaBGP.
                      In this case, the representation of this attribute will be a string.
                      If flags is an instance of BGPAttribute, the hexadecimal representation will be used
        """

        assert (not isinstance(attr_type, int)) or (flags is not None), "If Attr Type is int, flags must be set !"

        if flags is None:
            if str(attr_type) not in self._known_attr:
                raise ValueError("{unk_attr} is not a known attribute".format(unk_attr=str(attr_type)))
        elif not is_hex_str(val):
            raise ValueError("{val} is not an hexadecimal string !".format(val=val))

        self.flags = flags
        self.type = attr_type
        self.val = val

    def __str__(self):
        if self.flags is None:
            return self.str_repr()
        return self.hex_repr()

    def __repr__(self) -> str:
        return "BGPAttribute(attr_type={attr_type}, val={val}{flags})".format(
            attr_type=self.type, val=self.val,
            flags=" flags={val}".format(val=self.flags.hex_repr() if self.flags is not None else ""))


class BGPRoute(object):
    def __init__(self, ip_network, attributes: Sequence['BGPAttribute']):
        self.network = ip_network
        self.attributes = attributes

    def get_af(self):
        if isinstance(self.network, IPv4Network):
            return IPV4_UNICAST()
        elif isinstance(self.network, IPv6Network):
            return IPV6_UNICAST()
        else:
            raise ValueError("Unknown AF: {}".format(type(self.network)))

    def to_str(self, bgp_implem):
        return bgp_implem.route_to_str(self)


class AFISAFI(Singleton):

    def afi_str(self, bgp_implem):
        raise NotImplementedError
        return bgp_implem.afi_str(self)

    def to_str(self, bgp_implem):
        raise NotImplementedError
        return bgp_implem.afi_safi_str(self)


class Direction(Singleton):
    def to_str(self, bgp_implem):
        raise NotImplementedError()


class DirOut(Direction):
    def to_str(self, bgp_implem):
        return bgp_implem.direction_str(self)


class DirIn(Direction):
    def to_str(self, bgp_implem):
        return bgp_implem.direction_str(self)


class IPV4_UNICAST(AFISAFI):
    def __str__(self):
        return IPV4

    def __repr__(self):
        return str(self)


class IPV6_UNICAST(AFISAFI):
    def __str__(self):
        return IPV6

    def __repr__(self):
        return str(self)


class BGPImplem(Singleton):
    MAKO_TEMPLATE = ''
    IMPLEM_NAME = ''
    __CONFIG_DIR = "./configs"

    @property
    def template(self):
        return os.path.join(os.path.dirname(__file__), BGPImplem.__CONFIG_DIR, self.MAKO_TEMPLATE)

    @property
    def implem_name(self):
        return self.IMPLEM_NAME

    def afi_safi_str(self, afi_safi):
        raise NotImplementedError()

    def direction_str(self, direction):
        raise NotImplementedError()

    def afi_str(self, afi_safi):
        raise NotImplementedError()

    def route_to_str(self, bgp_route):
        raise NotImplementedError()

    def acl_list_str(self, access_list: 'AccessList'):
        raise NotImplementedError()

    def get_output_filename(self, node):
        return "{name}_{implem}.conf".format(name=node.name,
                                             implem=self.implem_name)

    def get_template(self):
        return Template(filename=self.template)

    def vpn_leak(self, af_conf):
        raise NotImplementedError()

    def write_config(self, node, output_dir, config):
        af_list = [IPV4_UNICAST(), IPV6_UNICAST()]
        out_file = os.path.join(output_dir, self.get_output_filename(node))

        node.output_path = out_file

        template = self.get_template()

        with open(out_file, 'w') as f:
            try:
                f.write(template.render(node=node, afis=af_list, acls=config.acl_filters,
                                        process=config.api_process))
            except:
                print(mako_exception.text_error_template().render())
                raise mako_exception.MakoException


class FRR(BGPImplem):
    def direction_str(self, direction):
        if isinstance(direction, DirIn):
            return 'in'
        elif isinstance(direction, DirOut):
            return 'out'
        else:
            ValueError("Unknown direction")

    MAKO_TEMPLATE = 'bgpd.conf.mako'
    IMPLEM_NAME = "bgpd"

    @property
    def __afi(self):
        return {
            AddressFamilyConfig.AFI_IPV4: 'ipv4',
            AddressFamilyConfig.AFI_IPV6: 'ipv6',
        }

    @property
    def __safi(self):
        return {
            AddressFamilyConfig.SAFI_UNICAST: 'unicast'
        }

    def afi_safi_str(self, afi_safi):
        return f'{self.__afi[afi_safi.afi]} {self.__safi[afi_safi.safi]}'

    def vpn_leak(self, af_conf: 'AddressFamilyConfig'):
        _dir = {
            AddressFamilyConfig.IMPORT: 'import',
            AddressFamilyConfig.EXPORT: 'export'
        }
        fin_str = f'rd vpn export {af_conf.rd}' if af_conf.rd else ''

        if af_conf.rt:
            for direction in af_conf.rt:
                fin_str += f"rt vpn {_dir[direction]} {af_conf.rt[direction].join(' ')}\n"

        if af_conf.rt:
            for direction in af_conf.vpn:
                fin_str += f'{_dir[direction]} vpn'

        return fin_str

    def route_to_str(self, bgp_route):
        return "{address}/{prefix}". \
            format(address=str(bgp_route.network
                               .network_address),
                   prefix=bgp_route.network.prefixlen)

    def acl_list_str(self, access_list: 'AccessList'):
        final_str = ''
        prefix = 'ipv6 ' if access_list.af == IPV6 else ''

        for auth, net in access_list.networks:
            if auth == PERMIT:
                auth_frr = 'permit'
            elif auth == DENY:
                auth_frr = "deny"
            else:
                raise ValueError("auth is not recognised ?!")

            if isinstance(net, str):
                if net == 'all':
                    network = 'any'
                else:
                    raise ValueError("net urecognised")
            else:
                network = str(net)

            final_str += f"{prefix}access-list {access_list.name} {auth_frr} {network}"
            final_str += '\n'

        return final_str

    def write_config(self, node, output_dir, config):
        super().write_config(node, output_dir, config)

        # FRRouting needs zebra configution file
        Zebra().write_config(node, output_dir, config)


class BIRD(BGPImplem):
    def direction_str(self, direction):
        if isinstance(direction, DirIn):
            return 'import'
        elif isinstance(direction, DirOut):
            return 'export'
        else:
            ValueError("Unknown direction")

    def acl_list_str(self, access_list: 'AccessList'):
        final_str = f"filter {access_list.name} {{\n"

        for auth, net in access_list.networks:
            if auth == PERMIT:
                auth_bird = "accept"
            elif auth == DENY:
                auth_bird = "reject"
            else:
                raise ValueError("Auth unrecognized")

            if isinstance(net, str):
                if net == 'all':
                    network = auth_bird
                    auth_bird = ''
                else:
                    raise ValueError("net urecognised")
            else:
                network = f"if net = {str(net)} then"

            final_str += f"    {network} {auth_bird};\n"

        final_str += "}"

        return final_str

    MAKO_TEMPLATE = 'bird.conf.mako'
    IMPLEM_NAME = 'bird'

    def afi_safi_str(self, afi_safi: 'AddressFamilyConfig'):
        afi = {
            AddressFamilyConfig.AFI_IPV4: 'ipv4',
            AddressFamilyConfig.AFI_IPV6: 'ipv6',
        }

        return f'{afi[afi_safi.afi]}'

    def route_to_str(self, bgp_route):
        raise UnsupportedOperation("We do not support route injection with BIRD yet")


class EXABGP(BGPImplem):
    MAKO_TEMPLATE = 'exabgp.conf.mako'
    IMPLEM_NAME = 'exabgp'

    @property
    def __afi(self):
        return {
            AddressFamilyConfig.AFI_IPV4: 'ipv4',
            AddressFamilyConfig.AFI_IPV6: 'ipv6',
        }

    @property
    def __safi(self):
        return {
            AddressFamilyConfig.SAFI_UNICAST: 'unicast'
        }

    def afi_safi_str(self, afi_safi):
        return f'{self.__afi[afi_safi.afi]} {self.__safi[afi_safi.safi]}'

    def afi_str(self, afi_safi):
        return f'{self.__afi[afi_safi.afi]}'

    def route_to_str(self, bgp_route: 'BGPRoute'):
        # we only handle unicast ipv4 and ipv6 routes
        return "unicast {network} {attributes}".format(
            network=str(bgp_route.network),
            attributes=" ".join([str(it) for it in bgp_route.attributes])
        )

    def write_config(self, node, output_dir, config):
        super().write_config(node, output_dir, config)

        # ExaBGP needs an extra configuration file to work
        EXABGPENV().write_config(node, output_dir, config)


class EXABGPENV(BGPImplem, Singleton):
    MAKO_TEMPLATE = 'exabgp.conf.env.mako'
    IMPLEM_NAME = 'exabgp.env'

    DEFAULT_VARS = {
        'daemon': {
            'user': 'root',
            'drop': 'false',
            'daemonize': 'false',
            'pid': '/tmp/exabgp_unique.pid'
        },
        'log': {
            'level': 'CRIT',
            'destination': '/tmp/exabgp_unique.log',
            'reactor': 'false',
            'processes': 'false',
            'network': 'false'
        },
        'api': {
            'cli': 'false'
        },
        'tcp': {
            'delay': 1
        }
    }

    def afi_safi_str(self, afi_safi):
        raise UnsupportedOperation("This is not a real routing configuration file")

    def route_to_str(self, bgp_route):
        raise UnsupportedOperation("This is not a real routing configuration file")

    def write_config(self, node, output_dir, config):
        template = self.get_template()
        out = os.path.join(output_dir, self.get_output_filename(node))

        with open(out, 'w') as f:
            f.write(template.render(env=self.DEFAULT_VARS))


class Zebra(BGPImplem):
    MAKO_TEMPLATE = 'zebra.conf.mako'
    IMPLEM_NAME = "zebra"

    def afi_safi_str(self, afi_safi):
        raise UnsupportedOperation("This is not a real routing configuration file")

    def direction_str(self, direction):
        raise UnsupportedOperation("This is not a real routing configuration file")

    def afi_str(self, afi_safi):
        raise UnsupportedOperation("This is not a real routing configuration file")

    def route_to_str(self, bgp_route):
        raise UnsupportedOperation("This is not a real routing configuration file")

    def acl_list_str(self, access_list: 'AccessList'):
        raise UnsupportedOperation("This is not a real routing configuration file")

    def write_config(self, node, output_dir, config):
        template = self.get_template()
        out = os.path.join(output_dir, self.get_output_filename(node))

        node.extra_config['zebra'] = out

        with open(out, 'w') as f:
            f.write(template.render(node=node))


class NeighborConfig(object):
    def __init__(self, neighbor: 'NodeConfig'):
        self._neighbor = neighbor
        self._ip = 0
        self._local_ip = 0
        self.asn = 0
        self.name = None
        self.holdtime = 240
        self.processes = list()
        self.description = None
        self.is_rr_client = False
        self.acl_filters = {
            IPV4: list(),
            IPV6: list(),
        }

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, NeighborConfig):
            return False
        return o._neighbor == self._neighbor

    def __hash__(self) -> int:
        return hash(self._neighbor.name)

    def set_ip(self, ip):
        self._ip = ip

    def set_asn(self, asn):
        self.asn = asn

    def set_description(self, desc):
        self.description = desc

    def set_local_ip(self, ip):
        self._local_ip = ip

    def set_holdtime(self, holdtime):
        self.holdtime = holdtime

    def add_process(self, name, cmdline):
        if name in self._neighbor.config.api_process:
            raise ValueError(f"{name} is already used !")
        self.processes.append(name)
        self._neighbor.config.api_process[name] = cmdline

    def set_filter_acl(self, acl: 'AccessList', direction: Direction):
        self.acl_filters[acl.af].append((acl, direction))

    def has_acl_from_af(self, af):
        if af not in self.acl_filters:
            return False
        return len(self.acl_filters[af]) > 0

    def set_rr_client(self):
        self.is_rr_client = True

    def unset_rr_client(self):
        self.is_rr_client = False

    @property
    def ip(self):
        return self._ip

    @property
    def local_ip(self):
        return self._local_ip


class AddressFamilyConfig(object):
    IMPORT = 'import'
    EXPORT = 'export'
    AFI_IPV4 = 1
    AFI_IPV6 = 2
    SAFI_UNICAST = 1

    def __init__(self, afi, safi):
        self.afi = afi
        self.safi = safi
        self.rd = None
        self.rt = None
        self.vpn = None

    def __eq__(self, o: object) -> bool:
        if isinstance(o, AddressFamilyConfig):
            return o.afi == self.afi and o.safi == self.safi
        return False

    def __hash__(self) -> int:
        return hash((self.afi, self.safi))

    def add_rt(self, direction, rt_value):
        if self.rt is None:
            self.rt = {direction: set()}
        if direction not in self.rt:
            self.rt[direction] = set()

        self.rt[direction].add(rt_value)

    def add_rd(self, rd_value):
        self.rd = rd_value

    def import_vpn(self):
        if self.vpn is None:
            self.vpn = set()
        self.vpn.add(self.IMPORT)

    def export_vpn(self):
        if self.vpn is None:
            self.vpn = set()
        self.vpn.add(self.EXPORT)

    def afi_str(self, bgp_implem):
        return bgp_implem.afi_str(self)

    def to_str(self, bgp_implem):
        return bgp_implem.afi_safi_str(self)

    def vpn_leak(self, bgp_implem):
        return bgp_implem.vpn_leak(self)


class NodeBGPConfig(object):
    DEFAULT_VRF = 'default'

    def __init__(self, proto_suite, config, vrf: Union[None, str] = None):
        self.proto_suite = proto_suite
        self.asn = -1
        self.router_id = -1
        self.neighbors = set()
        self.af = set()
        self.routes = {
            IPV4_UNICAST(): list(),
            IPV6_UNICAST(): list()
        }
        self.description = None
        self.__config = config  # type: Config
        self.__output_path = None
        self.vrf = vrf

    def is_default_vrf(self):
        if self.vrf is None:
            return True
        return self.vrf == self.DEFAULT_VRF

    @property
    def output_path(self):
        if self.__output_path is None:
            raise ValueError("Config not written yet!")
        return self.__output_path

    @output_path.setter
    def output_path(self, val):
        self.__output_path = val

    @property
    def config(self):
        return self.__config

    def set_as(self, asn):
        self.asn = asn

    def activate_af(self, afi, safi):
        af_config = AddressFamilyConfig(afi, safi)
        if af_config in self.af:
            raise ValueError(f"Address Family ({afi}, {safi}) already configured !")
        self.af.add(af_config)
        return af_config

    def set_router_id(self, router_id):
        self.router_id = router_id

    def add_route(self, route):
        self.routes[route.get_af()].append(route)

    def has_routes(self, af=None):
        if af is not None:
            if af not in self.routes:
                return False
            return len(self.routes[af]) > 0

        for af in self.routes:
            if len(self.routes[af]) > 0:
                return True
        return False

    def add_neighbor(self, neighbor_node, ip, local_ip):
        if neighbor_node not in self.neighbors:
            neighbor_conf = NeighborConfig(neighbor_node)
            neighbor_conf.set_ip(ip)
            neighbor_conf.set_local_ip(local_ip)
            self.neighbors.add(neighbor_conf)
        else:
            raise ValueError("{node} is already added to "
                             "the list of neighbors".format(node=neighbor_node.name))

        return neighbor_conf


class NodeConfig(object):
    def __init__(self, name, proto_suite, config: 'Config'):
        self.name = name
        self.config = config
        self._bgp_config = dict()
        self.log_file = None
        self.debugs = list()
        self.password = None
        self.proto_suite = proto_suite
        self.router_id = -1
        self.extra_config = dict()

    def add_bgp_config(self, vrf: str = NodeBGPConfig.DEFAULT_VRF):
        if vrf in self._bgp_config:
            raise ValueError("{name} is already configured for vrf {vrf} !".format(name=self.name, vrf=vrf))
        new_bgp_config = NodeBGPConfig(self.proto_suite, self.config, vrf)
        self._bgp_config[vrf] = new_bgp_config
        return new_bgp_config

    @property
    def bgp_config(self):
        return self._bgp_config

    def set_router_id(self, router_id):
        self.router_id = router_id

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, o: object) -> bool:
        if not isinstance(NodeConfig, o):
            return False
        return o.name == self.name

    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self.name)

    def write_config(self, output_dir, config):
        self.proto_suite.write_config(self, output_dir, config)


class Config(object):
    def __init__(self, output_dir):
        self._nodes = dict()
        self._output_dir = output_dir
        self.api_process = dict()
        self.acl_filters = dict()  # type: Dict[str, AccessList]

    def new_node(self, name: str, suite):
        if name not in self._nodes:
            node_conf = NodeConfig(name, suite, self)
            self._nodes[node_conf] = node_conf
        else:
            raise ValueError("{name} is already configured !".format(name=name))
        return node_conf

    def make_link(self, node1, node2, ip_node1, ip_node2,
                  vrf_node1=NodeBGPConfig.DEFAULT_VRF, vrf_node2=NodeBGPConfig.DEFAULT_VRF):
        if node1 not in self._nodes:
            raise ValueError("{node} not yet created".format(node=str(node1)))

        if node2 not in self._nodes:
            raise ValueError("{node} not yet created".format(node=str(node2)))

        if vrf_node1 not in self._nodes[node1].bgp_config:
            raise ValueError("vrf {vrf} not configured for {node}".format(vrf=vrf_node1, node=node1))

        if vrf_node2 not in self._nodes[node2].bgp_config:
            raise ValueError("vrf {vrf} not configured for {node}".format(vrf=vrf_node2, node=node2))

        n1_neigh_config = self._nodes[node1].bgp_config[vrf_node1].add_neighbor(node2, ip_node2, local_ip=ip_node1)
        n2_neigh_config = self._nodes[node2].bgp_config[vrf_node2].add_neighbor(node1, ip_node1, local_ip=ip_node2)

        n1_neigh_config.set_asn(self._nodes[node2].bgp_config[vrf_node2].asn)
        n2_neigh_config.set_asn(self._nodes[node1].bgp_config[vrf_node1].asn)
        n1_neigh_config.name = node2.name
        n2_neigh_config.name = node1.name

        return n1_neigh_config, n2_neigh_config

    def new_acl_filter(self, name, af):
        assert any(af == x for x in [IPV4, IPV6]), "Unrecognized address family '%s', expected 'IPV4' or 'IPV6'" % af

        if name in self.acl_filters:
            raise ValueError(f"{name} is already used as acl filter !")

        acl = AccessList(name, af)
        self.acl_filters[name] = acl
        return acl

    def __getattr__(self, name: str) -> Any:
        return getattr(self._neighbor, name)

    def write_conf(self):
        for node in self._nodes.values():
            node.write_config(self._output_dir, self)

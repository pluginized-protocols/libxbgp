import json
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network


class ExtraConfVarElem(object):
    TYPE_ARG = None

    def get_val(self):
        return NotImplementedError

    def to_dict(self):
        return {
            'type_arg': self.TYPE_ARG,
            'arg': self.get_val()
        }


class ExtraConfVarElemInt(ExtraConfVarElem, int):
    TYPE_ARG = 'int'

    def __new__(cls, x):
        return super().__new__(cls, x)

    def get_val(self):
        return int(self)


class ExtraConfVarElemDouble(ExtraConfVarElem, float):
    TYPE_ARG = 'double'

    def __new__(cls, x):
        return super().__new__(cls, x)

    def get_val(self):
        return float(self)


class ExtraConfVarElemIPv4(ExtraConfVarElem, IPv4Address):
    TYPE_ARG = 'ipv4'

    def get_val(self):
        return str(self)


class ExtraConfVarElemIPv6(ExtraConfVarElem, IPv6Address):
    TYPE_ARG = 'ipv6'

    def get_val(self):
        return str(self)


class ExtraConfVarElemIPv4Prefix(ExtraConfVarElem, IPv4Network):
    TYPE_ARG = 'ipv4_prefix'

    def get_val(self):
        return str(self)


class ExtraConfVarElemIPv6Prefix(ExtraConfVarElem, IPv6Network):
    TYPE_ARG = 'ipv6_prefix'

    def get_val(self):
        return str(self)


class ExtraConfVarElemList(ExtraConfVarElem, list):
    TYPE_ARG = 'list'

    def get_val(self):
        return [elem.to_dict() for elem in self]


class ExtraConfVarElemDict(ExtraConfVarElem, dict):
    TYPE_ARG = 'dict'

    def get_val(self):
        return {key: self[key].to_dict() for key in self}


class ExtraConf(dict):
    def __setattr__(self, key, value):
        self[key] = value

    def __getattr__(self, item):
        return self[item]

    def __prepare(self):
        return {
            'conf': {key: self[key].to_dict() for key in self}
        }

    def to_json(self):
        return json.dumps(self.__prepare())

    def write_conf(self, file):
        with open(file, 'w') as f:
            json.dump(self.__prepare(), f)

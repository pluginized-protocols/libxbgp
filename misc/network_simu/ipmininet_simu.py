from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import OSPF, RouterConfig, Zebra
from ipmininet import DEBUG_FLAG

from mininet.log import lg, LEVELS


class ZebraMod(Zebra):
    NAME = "zebra"
    PATH = "/usr/lib/frr/zebra"


class TopoTest(IPTopo):

    def __init__(self, *args, **kwargs):
        super(TopoTest, self).__init__(*args, **kwargs)

    def pluginized_ospf(self, name):
        r = self.addRouter(name)
        # Override "default_cfg_class" since we add custom OSPF
        r.addDaemon(OSPF, path='/usr/lib/frr/ospfd',
                    depends=(ZebraMod,),
                    kill_patterns=('/usr/lib/ospfd',),
                    default_cfg_class=RouterConfig)
        return r

    def build(self, *args, **kwargs):
        r1 = self.pluginized_ospf('r1')
        r2 = self.pluginized_ospf('r2')
        r3 = self.pluginized_ospf('r3')

        self.addLink(r1, r2)
        self.addLink(r2, r3)
        self.addLink(r3, r1)


if __name__ == '__main__':
    lg.setLogLevel('info')
    DEBUG_FLAG = True
    net = IPNet(topo=TopoTest())
    net.start()
    IPCLI(net)
    net.stop()

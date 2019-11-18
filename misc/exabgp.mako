neighbor ${router.neighbor.ip} {
  router-id ${router.id};
  local-address ${router.ip};
  local-as ${router.asn};
  peer-as ${router.neighbor.asn};
  group-updates false;

  family {
      ipv4 unicast;
  }

  announce {
    ipv4 {
   % for route in router.routes:
      unicast ${route['prefix']} next-hop self as-path ${route['as_path']} community ${route['communities']};
   % endfor
    }
  }
}
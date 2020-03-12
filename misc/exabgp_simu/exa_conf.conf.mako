process announce {
  run ./announce_routes.py ${conf['file']};
  encoder text;
}

template {
  neighbor controller {
    family {
      ipv4 unicast;
    }

    api connection {
      processes [ announce ];
      send {
        parsed;
        update;
      }
    }
  }
}

% for neighbor in conf['neighbors']:

neighbor ${neighbor['peer-address']} {
  inherit controller;
  local-as ${neighbor['local-as']};
  peer-as ${neighbor['remote-as']};
  hold-time ${neighbor['hold-time']};
  local-address ${neighbor['local-address']};
  router-id ${neighbor['router-id']};
}
% endfor
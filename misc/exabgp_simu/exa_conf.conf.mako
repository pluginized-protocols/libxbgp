% for neighbor in conf['neighbors']:
process ${neighbor['name-process']} {
  run ./announce_routes.py ${neighbor['name-process']}.json ${conf['file']};
  encoder text;
}

% endfor

template {
  neighbor controller {
    family {
      ipv4 unicast;
    }
  }

  group-update;

}

% for neighbor in conf['neighbors']:

neighbor ${neighbor['peer-address']} {
  inherit controller;
  local-as ${neighbor['local-as']};
  peer-as ${neighbor['remote-as']};
  hold-time ${neighbor['hold-time']};
  local-address ${neighbor['local-address']};
  router-id ${neighbor['router-id']};

  api connection_${neighbor['local-as']}_${neighbor['remote-as']} {
    processes [ ${neighbor['name-process']} ];
    send {
      parsed;
      update;
    }
  }

}
% endfor
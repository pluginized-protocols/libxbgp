% for neighbor in conf['neighbors']:
    % if not neighbor['passive']:
process ${neighbor['name']} {
  run ./announce_routes.py ${neighbor['name']}.json ${conf['file']};
  encoder text;
}
    % endif
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

    % if neighbor['passive']:
  passive;
    % else:
  api connection_${neighbor['local-as']}_${neighbor['remote-as']} {
    processes [ ${neighbor['name']} ];
    send {
      parsed;
      update;
    }
  }
    % endif

}
% endfor
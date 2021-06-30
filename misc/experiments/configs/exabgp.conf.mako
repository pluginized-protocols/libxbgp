%for c in process:
process ${c} {
  run ${process[c]};
  encoder json;
}

%endfor
%for n in node.neighbors:

neighbor ${n.ip} {
 %if n.description:
  description ${n.description};
 %endif
  router-id ${node.router_id};
  local-address ${n.local_ip};
  local-as ${node.asn};
  peer-as ${n.asn};

<%doc>
  %if node.exabgp.passive:
  passive;
  %endif
</%doc>
  family {
   %for af in node.af:
    ${af.to_str(node.proto_suite)};
   %endfor
  }
  %if len(n.processes) > 0:

  api {
    processes [ ${' '.join(n.processes)} ];
    send {
      parsed;
    }
  }

  %endif
  % if node.has_routes():
  announce {
   %for af in node.af:
    %if node.has_routes(af):
    ${af.afi_str(node.proto_suite)} {
      %for route in node.routes[af]:
      ${route.to_str(node.proto_suite)};
      %endfor
    }
    %endif
   %endfor
  }
  %endif
}
%endfor
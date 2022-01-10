%for c in process:
process ${c} {
  run ${process[c]};
  encoder json;
}

%endfor
<%
bgp_conf = node.bgp_config['default']
%>
%for n in bgp_conf.neighbors:

neighbor ${n.ip} {
 %if n.description:
  description ${n.description};
 %endif
  router-id ${node.router_id};
  local-address ${n.local_ip};
  local-as ${bgp_conf.asn};
  peer-as ${n.asn};

<%doc>
  %if node.exabgp.passive:
  passive;
  %endif
</%doc>
  family {
   %for af in bgp_conf.af:
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
  % if bgp_conf.has_routes():
  announce {
   %for af in bgp_conf.af:
    %if bgp_conf.has_routes(af):
    ${af.afi_str(node.proto_suite)} {
      %for route in bgp_conf.routes[af]:
      ${route.to_str(node.proto_suite)};
      %endfor
    }
    %endif
   %endfor
  }
  %endif
}
%endfor
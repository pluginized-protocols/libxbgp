hostname ${node.name}
%if node.password:
password zebra
%else:
password zebra
%endif
!
%if node.log_file:
log file ${node.log_file}
!
%endif
%for debug in node.debugs:
debug ${debug}
%endfor
!
router bgp ${node.asn}
  bgp router-id ${node.router_id}
  no bgp default ipv4-unicast
  !
  %for neigh in node.neighbors:
  neighbor ${neigh.ip} remote-as ${neigh.asn}
    %if neigh.description:
  neighbor ${neigh.ip} description ${neigh.description}
    %endif
  %endfor
!
%for af in node.af:
address-family ${af.to_str(node.proto_suite)}
  %for neigh in node.neighbors:
  neighbor ${neigh.ip} activate
    %if neigh.has_acl_from_af(str(af)):
      %for acl, direction in neigh.acl_filters[str(af)]:
  neighbor ${neigh.ip} distribute-list ${acl.name} ${direction.to_str(node.proto_suite)}
      %endfor
    %endif
    %if node.has_routes(af):
      %for network in node.routes[af]:
  network ${network.to_str(node.proto_suite)}
      %endfor
    %endif
  %endfor
exit-address-family
!
%endfor
!
%for a in acls:
${acls[a].to_str(node.proto_suite)}
!
%endfor

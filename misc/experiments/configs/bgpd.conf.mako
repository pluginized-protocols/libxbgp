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
%for vrf in node.bgp_config:
<%
bgp_conf = node.bgp_config[vrf]
%>
%if bgp_conf.is_default_vrf():
router bgp ${bgp_conf.asn}
%else:
router bgp ${bgp_conf.asn} vrf ${vrf}
%endif
  bgp router-id ${node.router_id}
  no bgp default ipv4-unicast
  !
  %for neigh in bgp_conf.neighbors:
  neighbor ${neigh.ip} remote-as ${neigh.asn}
    %if neigh.description:
  neighbor ${neigh.ip} description ${neigh.description}
    %endif
  neighbor ${neigh.ip} update-source ${neigh.local_ip}
    %if neigh.is_rr_client:
  neighbor ${neigh.ip} route-reflector-client
    %endif
  %endfor
!
%for af in bgp_conf.af:
 address-family ${af.to_str(bgp_conf.proto_suite)}
  ${af.vpn_leak(bgp_conf.proto_suite)}
  %for neigh in bgp_conf.neighbors:
  neighbor ${neigh.ip} activate
    %if neigh.has_acl_from_af(af.str_afi()):
      %for acl, direction in neigh.acl_filters[af.str_afi()]:
  neighbor ${neigh.ip} distribute-list ${acl.name} ${direction.to_str(bgp_conf.proto_suite)}
      %endfor
    %endif
    %if bgp_conf.has_routes(af):
      %for network in bgp_conf.routes[af]:
  network ${network.to_str(bgp_conf.proto_suite)}
      %endfor
    %endif
  %endfor
 exit-address-family
!
%endfor
%endfor
!
%for a in acls:
${acls[a].to_str(node.proto_suite)}
!
%endfor

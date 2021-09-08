
%if node.log_file:
log "${node.log_file}" { debug, trace, info, remote, warning, error, auth, fatal, bug };
%endif

router id ${node.router_id};

# debug protocols all;
# debug protocols { events, states };

protocol device {
}

protocol direct {
	disabled;		# Disable by default
	ipv4;			# Connect to default IPv4 table
	ipv6;			# ... and to default IPv6 table
}

protocol kernel {
	ipv4 {			# Connect protocol to IPv4 table by channel
	      export all;	# Export to protocol. default is export none
	};
	learn;
}

protocol kernel {
    ipv6 {
        export all;
    };
    learn;
}

%for a in acls:
${acls[a].to_str(node.proto_suite)}

%endfor
%for vrf in node.bgp_config:
<%
bgp_config = node.bgp_config[vrf]
%>
%for neigh in bgp_config.neighbors:

protocol bgp ${neigh.name} {
  %if neigh.description:
  description "${neigh.description}";
  %endif
  local ${neigh.local_ip} as ${bgp_config.asn};
  neighbor ${neigh.ip} as ${neigh.asn};
  %if neigh.is_rr_client:
  rr client;
  %endif
  hold time ${neigh.holdtime};
  %for af in bgp_config.af:

  ${af.to_str(node.proto_suite)} {
    %for acl, direction in neigh.acl_filters[af.str_afi()]:
      ${direction.to_str(node.proto_suite)} filter ${acl.name} ;
    %endfor
  };
  %endfor
}
%endfor
%endfor
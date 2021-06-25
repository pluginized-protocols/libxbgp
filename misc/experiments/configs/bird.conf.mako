
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
	ipv6 { export all; };
}

%for a in acls:
${acls[a].to_str(node.proto_suite)}

%endfor
%for neigh in node.neighbors:

protocol bgp ${neigh.name} {
  %if neigh.description:
  description "${neigh.description}";
  %endif
  local ${neigh.local_ip} as ${node.asn};
  neighbor ${neigh.ip} as ${neigh.asn};
  hold time ${neigh.holdtime};
  %for af in node.af:

  ${af.to_str(node.proto_suite)} {
    %for acl, direction in neigh.acl_filters[str(af)]:
      ${direction.to_str(node.proto_suite)} filter ${acl.name} ;
    %endfor
  };
  %endfor
}
%endfor
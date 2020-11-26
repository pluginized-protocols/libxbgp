%for top_env in conf.keys():
[exabgp.${top_env}]
    %for sub_env in conf[top_env].keys():
${sub_env} = ${conf[top_env][sub_env]}
    %endfor

%endfor
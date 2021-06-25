%for top_ini in env.keys():

[exabgp.${top_ini}]
%for item in env[top_ini].keys():
${item} = ${env[top_ini][item]}
%endfor
%endfor